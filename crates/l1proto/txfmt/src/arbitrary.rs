use arbitrary::{Arbitrary, Unstructured};

use crate::MagicBytes;
use crate::magic::MAGIC_BYTES_LEN;

impl<'a> Arbitrary<'a> for MagicBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Map each random byte into an uppercase ASCII letter (A-Z).
        let bytes = <[u8; MAGIC_BYTES_LEN]>::arbitrary(u)?.map(|b| b'A' + b % 26);
        Ok(MagicBytes::new(bytes))
    }
}
