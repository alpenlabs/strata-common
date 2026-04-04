//! Test utilities.
use arbitrary::{Arbitrary, Unstructured};
use rand_core::OsRng;

const ARB_GEN_LEN: usize = 65_536;

pub struct ArbitraryGenerator {
    buf: Vec<u8>,
}

impl ArbitraryGenerator {
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; ARB_GEN_LEN],
        }
    }
    pub fn generate<'a, T: Arbitrary<'a> + Clone>(&'a mut self) -> T {
        OsRng.fill_bytes(&mut self.buf);
        T::arbitrary(&mut Unstructured::new(&self.buf)).expect("arbitrary failed")
    }
}
