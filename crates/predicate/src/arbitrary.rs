use arbitrary::{Arbitrary, Unstructured};

use crate::{PredicateKey, PredicateTypeId};

impl<'a> Arbitrary<'a> for PredicateTypeId {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choices = [
            PredicateTypeId::NeverAccept,
            PredicateTypeId::AlwaysAccept,
            PredicateTypeId::Bip340Schnorr,
            PredicateTypeId::Sp1Groth16,
        ];
        Ok(*u.choose(&choices)?)
    }
}

impl<'a> Arbitrary<'a> for PredicateKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let id = PredicateTypeId::arbitrary(u)?;
        let condition = Vec::<u8>::arbitrary(u)?;
        Ok(PredicateKey::new(id, condition))
    }
}
