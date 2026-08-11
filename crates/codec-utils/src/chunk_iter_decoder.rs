//! Decoder that reads from a sequence of byte chunks provided by an iterator.

use std::fmt;

use strata_codec::{CodecError, Decoder};

/// Decoder that pulls its input from an iterator of byte slices.
///
/// This makes it possible to decode a message that's split across a number of
/// noncontiguous buffers (like transaction payloads spread over several
/// envelopes) without having to concatenate them into a single buffer first.
/// Reads transparently span chunk boundaries.
///
/// Chunks are only pulled from the iterator as they're needed, so the iterator
/// may be lazy.  Empty chunks are skipped over.
///
/// The decoder is fused: once the iterator returns `None` we never call it
/// again and every subsequent read that needs more data fails with
/// [`CodecError::OverrunInput`], even if the iterator would have resumed
/// yielding chunks.
pub struct ChunkIterDecoder<'c, I> {
    /// Source of further chunks, after `cur` is exhausted.
    iter: I,

    /// Unread remainder of the chunk we're currently reading from.
    cur: &'c [u8],

    /// Total number of bytes read out so far, across all chunks.
    read: usize,

    /// If the iterator has returned `None`, after which we stop calling it.
    fused: bool,
}

impl<'c, I: Iterator<Item = &'c [u8]>> ChunkIterDecoder<'c, I> {
    /// Constructs a new instance from something we can iterate byte chunks out
    /// of.
    pub fn new(chunks: impl IntoIterator<Item = &'c [u8], IntoIter = I>) -> Self {
        Self {
            iter: chunks.into_iter(),
            cur: &[],
            read: 0,
            fused: false,
        }
    }

    /// Returns the total number of bytes that have been read out of the
    /// decoder.
    pub fn bytes_read(&self) -> usize {
        self.read
    }

    /// Returns the number of bytes remaining in the chunk we're currently
    /// reading from.
    ///
    /// This says nothing about how much data is left in the iterator, so it
    /// being 0 does *not* mean the decoder is exhausted.
    pub fn cur_chunk_remaining(&self) -> usize {
        self.cur.len()
    }

    /// Returns if there's no more data to be read, consuming chunks off the
    /// iterator until we find one that's nonempty or we run out.
    ///
    /// If we run out, this fuses the decoder.
    pub fn is_exhausted(&mut self) -> bool {
        !self.refill()
    }

    /// Ensures `cur` is nonempty, pulling chunks off the iterator as needed.
    ///
    /// Returns if there's data available to read.  Once the iterator returns
    /// `None` we set the fused flag and never call it again, so a misbehaving
    /// iterator can't make us loop forever or resurrect the stream.
    fn refill(&mut self) -> bool {
        while self.cur.is_empty() {
            if self.fused {
                return false;
            }

            match self.iter.next() {
                Some(next) => self.cur = next,
                None => {
                    self.fused = true;
                    return false;
                }
            }
        }

        true
    }

    /// Copies bytes into `into`, spanning chunks as necessary.
    fn read_into(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
        let mut at = 0;

        while at < into.len() {
            if !self.refill() {
                return Err(CodecError::OverrunInput);
            }

            let take = usize::min(into.len() - at, self.cur.len());
            into[at..at + take].copy_from_slice(&self.cur[..take]);
            self.cur = &self.cur[take..];
            at += take;
            self.read += take;
        }

        Ok(())
    }
}

impl<'c, I: Iterator<Item = &'c [u8]>> Decoder for ChunkIterDecoder<'c, I> {
    fn read_buf(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
        self.read_into(into)
    }

    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut buf = [0; N];
        self.read_into(&mut buf)?;
        Ok(buf)
    }
}

impl<I> fmt::Debug for ChunkIterDecoder<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkIterDecoder")
            .field("cur_chunk_remaining", &self.cur.len())
            .field("read", &self.read)
            .field("fused", &self.fused)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use strata_codec::{Codec, Decoder};

    use super::ChunkIterDecoder;

    #[test]
    fn test_read_across_chunks() {
        let chunks: Vec<&[u8]> = vec![&[0, 1, 2], &[3, 4], &[5, 6, 7, 8, 9]];
        let mut dec = ChunkIterDecoder::new(chunks.iter().copied());

        assert_eq!(dec.read_arr::<2>().expect("test: read"), [0, 1]);

        let mut buf = [0; 6];
        dec.read_buf(&mut buf).expect("test: read");
        assert_eq!(buf, [2, 3, 4, 5, 6, 7]);

        assert_eq!(dec.read_arr::<2>().expect("test: read"), [8, 9]);
        assert_eq!(dec.bytes_read(), 10);
        assert!(dec.is_exhausted());
    }

    /// Iterator that returns `None` once and then starts yielding chunks again,
    /// which we should never see because the decoder fuses.
    struct Resuming {
        calls: usize,
    }

    impl Iterator for Resuming {
        type Item = &'static [u8];

        fn next(&mut self) -> Option<Self::Item> {
            self.calls += 1;
            match self.calls {
                1 => Some(&[1, 2]),
                2 => None,
                _ => Some(&[3, 4]),
            }
        }
    }

    #[test]
    fn test_fused_after_none() {
        let mut dec = ChunkIterDecoder::new(Resuming { calls: 0 });

        assert_eq!(dec.read_arr::<2>().expect("test: read"), [1, 2]);

        // This exhausts the iterator, fusing us.
        assert!(dec.read_arr::<1>().is_err());

        // Even though the iterator would yield more, we're done.
        assert!(dec.is_exhausted());
        assert!(dec.read_arr::<1>().is_err());
        assert_eq!(dec.bytes_read(), 2);
    }

    #[test]
    fn test_read_exact_then_overrun() {
        let chunks: Vec<&[u8]> = vec![&[1, 2], &[], &[3]];
        let mut dec = ChunkIterDecoder::new(chunks.iter().copied());

        let mut buf = [0; 3];
        dec.read_buf(&mut buf).expect("test: read");
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(dec.bytes_read(), 3);
        assert!(dec.is_exhausted());

        assert!(dec.read_arr::<1>().is_err());
    }

    #[test]
    fn test_empty_read_ok() {
        let chunks: Vec<&[u8]> = Vec::new();
        let mut dec = ChunkIterDecoder::new(chunks.iter().copied());

        dec.read_buf(&mut []).expect("test: read");
        assert!(dec.read_arr::<1>().is_err());
    }

    #[test]
    fn test_decode_type_across_chunks() {
        let v = 0x0123456789abcdefu64;
        let encoded = v.to_be_bytes();
        let chunks: Vec<&[u8]> = vec![&encoded[..1], &encoded[1..5], &encoded[5..]];
        let mut dec = ChunkIterDecoder::new(chunks.iter().copied());

        assert_eq!(u64::decode(&mut dec).expect("test: decode"), v);
        assert!(dec.is_exhausted());
    }
}
