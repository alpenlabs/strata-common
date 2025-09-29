//! Example of how consumers would use the generate_codec_tests! macro.

#![expect(missing_docs, reason = "test repo")]
#![expect(unused_crate_dependencies, reason = "macro hacks")]

use strata_codec_tests::{
    generate_codec_tests,
    proptest::prelude::*,
    strata_codec::{Codec, CodecError, Decoder, Encoder},
};

// Example: Consumer defines their own type with manual Codec implementation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomMessage {
    version: u8,
    payload: Vec<u8>,
}

impl Codec for CustomMessage {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let version = u8::decode(dec)?;
        let len = u32::decode(dec)?;
        let mut payload = vec![0u8; len as usize];
        dec.read_buf(&mut payload)?;
        Ok(CustomMessage { version, payload })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.version.encode(enc)?;
        (self.payload.len() as u32).encode(enc)?;
        enc.write_buf(&self.payload)
    }
}

impl Arbitrary for CustomMessage {
    type Parameters = ();
    type Strategy = BoxedStrategy<CustomMessage>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<u8>(),
            strata_codec_tests::proptest::collection::vec(any::<u8>(), 0..100),
        )
            .prop_map(|(version, payload)| CustomMessage { version, payload })
            .boxed()
    }
}

// Consumer uses the macro to generate comprehensive property tests
generate_codec_tests!(CustomMessage, "custom_message");
