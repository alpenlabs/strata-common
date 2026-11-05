use bitcoin::taproot::LeafVersion;
use bitcoin::{OutPoint, Script, TxIn};

use super::envelope::{SignedEnvelopeLeaf, parse_signed_envelope_leaf};
use super::errors::SignedEnvelopeSpendError;

/// A signed envelope leaf revealed by a taproot script-path spend, before the
/// output it spends has been checked.
///
/// SPS-51 lets a consumer treat the spending input's signature as transitively
/// signing the envelope, so that the leaf pubkey stands in for a signature over
/// the payload. That holds only when Bitcoin consensus, in accepting the
/// spending transaction, verified a BIP340 signature by the leaf pubkey, which
/// requires all of:
///
/// 1. **The script is a strict signed envelope leaf**, as accepted by
///    [`parse_signed_envelope_leaf`], so a valid signature is the only way to satisfy it.
/// 2. **The leaf version is [`LeafVersion::TapScript`].** BIP341 executes no other leaf version and
///    requires such a spend to succeed unconditionally.
/// 3. **The spent output is a native P2TR output.** BIP341 interprets the witness of no other
///    output type: segwit v1 programs other than 32 bytes (P2A included), segwit v2 to v16, and
///    their P2SH-wrapped forms are unencumbered, so any witness spends them.
///
/// [`parse_signed_envelope_spend`] checks the first two, which the spending
/// transaction shows. The third needs the spent output, which a transaction
/// does not carry: [`verify_spent_output`](Self::verify_spent_output) checks it
/// and yields the authenticated leaf.
///
/// Every check assumes the spending transaction is confirmed in a block that
/// enforces BIP341, since before Taproot activation no witness spending a v1
/// output was executed. This crate cannot verify either, and an unconfirmed
/// transaction proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelopeSpend {
    leaf: SignedEnvelopeLeaf,
    spent_outpoint: OutPoint,
}

impl SignedEnvelopeSpend {
    /// The outpoint of the output the input spends, whose locking script
    /// [`verify_spent_output`](Self::verify_spent_output) needs.
    pub fn spent_outpoint(&self) -> OutPoint {
        self.spent_outpoint
    }

    /// The leaf, not yet authenticated.
    ///
    /// Use it to decide whether the spend is worth authenticating, such as by
    /// comparing its pubkey with an expected key before fetching the spent
    /// output. Nothing read from it is authenticated until
    /// [`verify_spent_output`](Self::verify_spent_output) succeeds.
    pub fn unverified_leaf(&self) -> &SignedEnvelopeLeaf {
        &self.leaf
    }

    /// Checks that the spent output, locked by `spent_script_pubkey`, is a
    /// native P2TR output, and returns the leaf, whose pubkey then stands in
    /// for a signature over its payload.
    ///
    /// `spent_script_pubkey` must be the locking script of the output at
    /// [`spent_outpoint`](Self::spent_outpoint).
    ///
    /// # Errors
    ///
    /// [`SignedEnvelopeSpendError::NonTaprootSpentOutput`] if
    /// `spent_script_pubkey` is not a native P2TR output.
    pub fn verify_spent_output(
        self,
        spent_script_pubkey: &Script,
    ) -> Result<SignedEnvelopeLeaf, SignedEnvelopeSpendError> {
        if !spent_script_pubkey.is_p2tr() {
            return Err(SignedEnvelopeSpendError::NonTaprootSpentOutput {
                script_pubkey: spent_script_pubkey.to_owned(),
            });
        }
        Ok(self.leaf)
    }

    /// Returns the leaf when the caller has already established that the spent
    /// output is a native P2TR output.
    pub(crate) fn into_leaf_spending_taproot(self) -> SignedEnvelopeLeaf {
        self.leaf
    }
}

/// Parses the signed envelope leaf revealed by `input` as a taproot script-path
/// spend.
///
/// Checks that the witness reveals a [`LeafVersion::TapScript`] leaf and that
/// the leaf is a strict signed envelope leaf. The output `input` spends must
/// still be checked with [`SignedEnvelopeSpend::verify_spent_output`] before
/// the leaf pubkey authenticates anything; see [`SignedEnvelopeSpend`].
///
/// # Errors
///
/// [`SignedEnvelopeSpendError`] if the witness reveals no leaf script, the leaf
/// version is not [`LeafVersion::TapScript`], or the leaf is not a strict
/// signed envelope leaf.
pub fn parse_signed_envelope_spend(
    input: &TxIn,
) -> Result<SignedEnvelopeSpend, SignedEnvelopeSpendError> {
    let leaf = input
        .witness
        .taproot_leaf_script()
        .ok_or(SignedEnvelopeSpendError::MissingLeafScript)?;
    if leaf.version != LeafVersion::TapScript {
        return Err(SignedEnvelopeSpendError::UnsupportedLeafVersion {
            version: leaf.version.to_consensus(),
        });
    }

    Ok(SignedEnvelopeSpend {
        leaf: parse_signed_envelope_leaf(leaf.script)?,
        spent_outpoint: input.previous_output,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::OP_NOT;
    use bitcoin::{ScriptBuf, ScriptHash, WScriptHash, Witness, WitnessProgram, WitnessVersion};

    use super::*;
    use crate::EnvelopeParseError;
    use crate::test_utils::*;

    fn witness_program_script(version: WitnessVersion, program: &[u8]) -> ScriptBuf {
        let program = WitnessProgram::new(version, program).expect("valid witness program");
        ScriptBuf::new_witness_program(&program)
    }

    fn reveal_input(leaf_version: LeafVersion) -> TxIn {
        build_unsupported_leaf_reveal_input(make_txid(1), 2, b"chunk", 11, leaf_version)
    }

    #[test]
    fn test_tapscript_spend_of_p2tr_output_authenticates_leaf() {
        let input = reveal_input(LeafVersion::TapScript);

        let spend = parse_signed_envelope_spend(&input).expect("tapscript leaf parses");
        assert_eq!(spend.spent_outpoint(), input.previous_output);

        let leaf = spend
            .verify_spent_output(&make_p2tr_script())
            .expect("native P2TR output authenticates");
        assert_eq!(leaf.pubkey(), &make_xonly_pubkey_bytes(11));
        assert_eq!(leaf.payload(), b"chunk");
    }

    /// BIP341 executes only tapscript leaves: under any other version the
    /// spend succeeds without running `OP_CHECKSIG`.
    #[test]
    fn test_every_non_tapscript_leaf_version_rejected() {
        let non_tapscript = (0..=u8::MAX)
            .step_by(2)
            .filter_map(|byte| LeafVersion::from_consensus(byte).ok())
            .filter(|version| *version != LeafVersion::TapScript);

        for leaf_version in non_tapscript {
            let error = parse_signed_envelope_spend(&reveal_input(leaf_version))
                .expect_err("non-tapscript leaf must be rejected");

            let expected = leaf_version.to_consensus();
            assert!(
                matches!(
                    error,
                    SignedEnvelopeSpendError::UnsupportedLeafVersion { version } if version == expected
                ),
                "leaf version {expected:#04x}: unexpected error {error:?}"
            );
        }
    }

    /// An annex shifts the leaf script and control block down one element;
    /// the parser must still find them.
    #[test]
    fn test_annex_does_not_hide_the_leaf() {
        let mut input = reveal_input(LeafVersion::TapScript);
        let mut witness: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
        witness.push(vec![0x50, 0xaa]);
        input.witness = Witness::from_slice(&witness);

        let leaf = parse_signed_envelope_spend(&input)
            .expect("annexed tapscript leaf parses")
            .verify_spent_output(&make_p2tr_script())
            .expect("native P2TR output authenticates");

        assert_eq!(leaf.payload(), b"chunk");
    }

    #[test]
    fn test_spend_without_leaf_script_rejected() {
        let key_path = Witness::from_slice(&[[1u8; 64]]);
        for witness in [Witness::new(), key_path] {
            let mut input = reveal_input(LeafVersion::TapScript);
            input.witness = witness;

            let error = parse_signed_envelope_spend(&input).expect_err("no leaf script");

            assert!(matches!(error, SignedEnvelopeSpendError::MissingLeafScript));
        }
    }

    #[test]
    fn test_non_strict_leaf_rejected() {
        let mut input = reveal_input(LeafVersion::TapScript);
        let mut witness: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
        // An empty signature makes OP_CHECKSIG push false; OP_NOT inverts it.
        witness[1].push(OP_NOT.to_u8());
        input.witness = Witness::from_slice(&witness);

        let error = parse_signed_envelope_spend(&input).expect_err("trailing opcode");

        assert!(matches!(
            error,
            SignedEnvelopeSpendError::InvalidLeaf(
                EnvelopeParseError::UnexpectedTrailingInstructions
            )
        ));
    }

    /// Bitcoin never executes the witness spending these outputs, so a
    /// tapscript-shaped witness proves nothing about the leaf pubkey.
    #[test]
    fn test_non_taproot_spent_outputs_rejected() {
        let v1_32 = witness_program_script(WitnessVersion::V1, &[0x11; 32]);
        let cases = [
            (
                "witness v2",
                witness_program_script(WitnessVersion::V2, &[0x11; 32]),
            ),
            (
                "witness v16",
                witness_program_script(WitnessVersion::V16, &[0x11; 32]),
            ),
            (
                "P2A",
                witness_program_script(WitnessVersion::V1, &[0x4e, 0x73]),
            ),
            (
                "v1 33-byte",
                witness_program_script(WitnessVersion::V1, &[0x11; 33]),
            ),
            ("P2SH-wrapped v1", ScriptBuf::new_p2sh(&v1_32.script_hash())),
            ("P2SH", ScriptBuf::new_p2sh(&ScriptHash::all_zeros())),
            ("P2WSH", ScriptBuf::new_p2wsh(&WScriptHash::all_zeros())),
        ];

        for (name, script_pubkey) in cases {
            let spend = parse_signed_envelope_spend(&reveal_input(LeafVersion::TapScript))
                .expect("tapscript leaf parses");

            let error = spend
                .verify_spent_output(&script_pubkey)
                .expect_err("non-taproot spent output must be rejected");

            assert!(
                matches!(
                    &error,
                    SignedEnvelopeSpendError::NonTaprootSpentOutput { script_pubkey: found }
                        if *found == script_pubkey
                ),
                "{name}: unexpected error {error:?}"
            );
        }
    }
}
