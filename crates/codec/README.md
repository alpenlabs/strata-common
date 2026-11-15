# strata-codec

This is a lightweight utility library for encoding binary messages.  It's
oriented towards small messages that comfortably fit in memory and assumes that
we're always reading out of a flat buffer (ie. that we're not reading from a
`Read`).

We currently use `borsh` to accomplish these tasks, but it's not well-suited for
the task and we are incrementally trying to migrate to either SSZ for general
types or, in this case, a more explicitly-defined encoding scheme.

This is essentially a fork of the codec scheme I (Trey Del Bonis) used in
another project of mine, being maintained independently so we can iterate on it
to aid in things like (maybe) making it more zero-copy friendly.

## Decode rules

Decoding is canonical by default: a value decodes only from the bytes its
`encode` writes, so a `Varint` with a longer layout than its value needs is
rejected rather than read. Every `Decoder` reports the rules it reads under
through `Decoder::rules`, and `BufDecoder::new` and `decode_buf_exact` use
`DecodeRules::Canonical`.

`DecodeRules::Lenient`, selected with `BufDecoder::with_rules` or
`decode_buf_exact_with_rules`, accepts the longer layouts the canonical rules
reject. It exists for bytes that were proven or signed before canonical
decoding was enforced and must keep decoding exactly as they did then. Use it
only where the input's provenance is known, such as replaying data under the
rules its proof used, and never for fresh input: under lenient rules one value
has several encodings, so anything that keys, deduplicates or hashes on the
bytes can be fed the same value twice. Length and overrun checks apply under
both rules.
