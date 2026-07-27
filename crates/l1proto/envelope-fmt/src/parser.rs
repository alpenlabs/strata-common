use bitcoin::Script;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Instruction, Instructions};

use crate::SIGNED_LEAF_PUBKEY_LEN;
use crate::builder::MAX_ENVELOPE_PAYLOAD_SIZE;
use crate::errors::EnvelopeParseError;

/// One parsed signed envelope leaf.
///
/// "Signed" is the script *shape* — a pubkey guarded by `OP_CHECKSIG` — not a
/// verified signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelopeLeaf {
    pubkey: [u8; SIGNED_LEAF_PUBKEY_LEN],
    payload: Vec<u8>,
}

impl SignedEnvelopeLeaf {
    /// The x-only public key the leaf's `OP_CHECKSIG` binds spending to.
    ///
    /// Callers authenticate by comparing these bytes against their own expected
    /// key; this crate applies no key policy.
    pub fn pubkey(&self) -> &[u8; SIGNED_LEAF_PUBKEY_LEN] {
        &self.pubkey
    }

    /// Concatenated payload bytes carried between `OP_IF` and `OP_ENDIF`.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the leaf, returning the payload bytes.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Parses and extracts the payload from a Bitcoin script envelope.
///
/// Extracts the raw payload bytes from a script containing an envelope structure
/// with the format: `OP_FALSE OP_IF <payload_chunks> OP_ENDIF`.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if the script doesn't contain a valid envelope structure
/// or if the payload data is malformed.
pub fn parse_envelope_payload(script: &Script) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut instructions = script.instructions();
    enter_envelope(&mut instructions)?;
    read_payload_until_endif(&mut instructions, usize::MAX)
}

/// Parses and extracts all payloads from a script with multiple envelopes.
///
/// Extracts payloads from a script containing multiple sequential envelopes.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if no valid envelopes are found, if any envelope
/// structure is invalid, or if any payload data is malformed.
pub fn parse_multi_envelope_payloads(script: &Script) -> Result<Vec<Vec<u8>>, EnvelopeParseError> {
    let mut instructions = script.instructions();
    let mut payloads = Vec::new();

    while enter_envelope(&mut instructions).is_ok() {
        let payload = read_payload_until_endif(&mut instructions, usize::MAX)?;
        payloads.push(payload);
    }

    if payloads.is_empty() {
        return Err(EnvelopeParseError::NoEnvelopesFound);
    }

    Ok(payloads)
}

/// A tuple-returning view of [`parse_signed_envelope_leaf`], kept for callers
/// that predate that type.
///
/// Enforces the same strict grammar and always returns exactly one payload; see
/// that function for the shape and the strictness rationale.
///
/// # Errors
///
/// Returns [`EnvelopeParseError`] if the script is not exactly one signed
/// envelope leaf.
pub fn parse_envelope_container(
    script: &Script,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), EnvelopeParseError> {
    let leaf = parse_signed_envelope_leaf(script)?;
    Ok((leaf.pubkey().to_vec(), vec![leaf.into_payload()]))
}

/// Parses a tapscript leaf that must be exactly one signed envelope:
///
/// ```text
/// <x-only pubkey> OP_CHECKSIG OP_FALSE OP_IF <data pushes> OP_ENDIF
/// ```
///
/// with no leading, interleaved, or trailing instructions (`OP_FALSE`, `OP_0`,
/// and an empty push are equivalent openers).
///
/// The strict shape authenticates only for a
/// [`LeafVersion::TapScript`](bitcoin::taproot::LeafVersion) leaf. This parses a script, not a
/// leaf, so the caller must confirm the leaf version itself.
///
/// The pubkey must be exactly [`SIGNED_LEAF_PUBKEY_LEN`] bytes — see
/// [`EnvelopeParseError::InvalidPubkeyLength`] for why a laxer rule breaks
/// authentication.
///
/// # Errors
///
/// [`EnvelopeParseError`] if the script deviates from the shape in any way, or
/// if the payload exceeds [`MAX_ENVELOPE_PAYLOAD_SIZE`].
pub fn parse_signed_envelope_leaf(
    script: &Script,
) -> Result<SignedEnvelopeLeaf, EnvelopeParseError> {
    let mut instructions = script.instructions();

    // Length is checked before OP_CHECKSIG so a bare envelope, whose OP_FALSE
    // decodes as an empty push, is reported as an invalid pubkey rather than a
    // missing OP_CHECKSIG.
    let pubkey_bytes = read_pubkey_push(&mut instructions)?;
    let pubkey = <[u8; SIGNED_LEAF_PUBKEY_LEN]>::try_from(pubkey_bytes).map_err(|_| {
        EnvelopeParseError::InvalidPubkeyLength {
            expected: SIGNED_LEAF_PUBKEY_LEN,
            found: pubkey_bytes.len(),
        }
    })?;
    expect_checksig(&mut instructions)?;

    // The opener must be the very next instruction; unlike the lenient
    // parsers, nothing may be skipped to reach it.
    match next_instruction(&mut instructions)? {
        Some(instruction) if is_envelope_opener(&instruction) => {}
        _ => return Err(EnvelopeParseError::MissingOpFalse),
    }

    expect_op_if(&mut instructions)?;

    let payload = read_payload_until_endif(&mut instructions, MAX_ENVELOPE_PAYLOAD_SIZE)?;

    if next_instruction(&mut instructions)?.is_some() {
        return Err(EnvelopeParseError::UnexpectedTrailingInstructions);
    }

    Ok(SignedEnvelopeLeaf { pubkey, payload })
}

/// Reads the next instruction, mapping a decode failure to
/// [`EnvelopeParseError::MalformedScript`].
///
/// Every strict read and the shared payload loop go through here, so an
/// undecodable instruction errors rather than being silently skipped. The one
/// place that skips it is [`enter_envelope`]'s forward scan for the opener.
fn next_instruction<'a>(
    instructions: &mut Instructions<'a>,
) -> Result<Option<Instruction<'a>>, EnvelopeParseError> {
    match instructions.next() {
        None => Ok(None),
        Some(Ok(instruction)) => Ok(Some(instruction)),
        Some(Err(_)) => Err(EnvelopeParseError::MalformedScript),
    }
}

/// Locates and validates the envelope start sequence (`OP_FALSE OP_IF`).
fn enter_envelope(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    // Scan forward for the opener, skipping anything else. Undecodable
    // instructions are skipped too.
    loop {
        match instructions.next() {
            None => return Err(EnvelopeParseError::MissingOpFalse),
            Some(Ok(instruction)) if is_envelope_opener(&instruction) => break,
            _ => continue,
        }
    }

    // Verify OP_FALSE is followed by OP_IF
    expect_op_if(instructions)?;
    Ok(())
}

/// Whether an instruction opens an envelope.
///
/// `OP_FALSE` pushes an empty byte array, so a decoded script usually presents
/// the opener as an empty push; the `OP_FALSE` and `OP_0` opcode forms are
/// accepted too. Shared by the lenient and strict parsers.
fn is_envelope_opener(instruction: &Instruction<'_>) -> bool {
    match instruction {
        Instruction::Op(op) => *op == OP_FALSE || *op == OP_0,
        Instruction::PushBytes(bytes) => bytes.as_bytes().is_empty(),
    }
}

/// Reads the pubkey push opening a signed leaf, unvalidated — length is the
/// caller's policy ([`SIGNED_LEAF_PUBKEY_LEN`] for a signed leaf).
///
/// Kept separate from [`expect_checksig`] so the length check falls between the
/// two: a bare envelope's `OP_FALSE` arrives here as a zero-length push, so the
/// strict parser reports an invalid pubkey rather than a missing checksig.
///
/// # Errors
///
/// [`EnvelopeParseError::MissingPubkey`] if the next instruction is not a push.
fn read_pubkey_push<'a>(
    instructions: &mut Instructions<'a>,
) -> Result<&'a [u8], EnvelopeParseError> {
    match next_instruction(instructions)? {
        Some(Instruction::PushBytes(bytes)) => Ok(bytes.as_bytes()),
        _ => Err(EnvelopeParseError::MissingPubkey),
    }
}

/// Consumes the `OP_CHECKSIG` guarding a container's pubkey.
///
/// # Errors
///
/// Returns [`EnvelopeParseError::MissingChecksig`] if the next instruction is
/// anything else.
fn expect_checksig(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    match next_instruction(instructions)? {
        Some(Instruction::Op(op)) if op == OP_CHECKSIG => Ok(()),
        _ => Err(EnvelopeParseError::MissingChecksig),
    }
}

/// Consumes the `OP_IF` that must follow an envelope opener.
///
/// # Errors
///
/// Returns [`EnvelopeParseError::MissingOpIf`] if the next instruction is
/// anything else.
fn expect_op_if(instructions: &mut Instructions<'_>) -> Result<(), EnvelopeParseError> {
    match next_instruction(instructions)? {
        Some(Instruction::Op(op)) if op == OP_IF => Ok(()),
        _ => Err(EnvelopeParseError::MissingOpIf),
    }
}

/// Concatenates payload pushes until `OP_ENDIF`.
///
/// `max` bounds the accumulated payload. Callers with no bound of their own
/// pass [`usize::MAX`].
///
/// # Errors
///
/// Returns [`EnvelopeParseError::UnexpectedOpcodeInPayload`] for a non-push
/// instruction before `OP_ENDIF`, [`EnvelopeParseError::MissingOpEndif`] if the
/// script ends first, or [`EnvelopeParseError::PayloadTooLarge`] if the payload
/// exceeds `max`.
fn read_payload_until_endif(
    instructions: &mut Instructions<'_>,
    max: usize,
) -> Result<Vec<u8>, EnvelopeParseError> {
    let mut payload = Vec::new();

    loop {
        match next_instruction(instructions)? {
            Some(Instruction::Op(op)) if op == OP_ENDIF => return Ok(payload),
            Some(Instruction::PushBytes(bytes)) => {
                payload.extend_from_slice(bytes.as_bytes());
                if payload.len() > max {
                    return Err(EnvelopeParseError::PayloadTooLarge {
                        total_size: payload.len(),
                        max,
                    });
                }
            }
            Some(Instruction::Op(_)) => {
                return Err(EnvelopeParseError::UnexpectedOpcodeInPayload);
            }
            None => return Err(EnvelopeParseError::MissingOpEndif),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::Builder;
    use bitcoin::constants::MAX_SCRIPT_ELEMENT_SIZE;
    use bitcoin::opcodes::OP_TRUE;
    use bitcoin::opcodes::all::{OP_ADD, OP_DROP, OP_NOT};
    use bitcoin::script::PushBytesBuf;
    use bitcoin::{Opcode, ScriptBuf};

    use super::*;
    use crate::builder::{EnvelopeScriptBuilder, MIN_ENVELOPE_PAYLOAD_SIZE, build_envelope_script};

    #[test]
    fn test_parse_envelope_data() {
        let small_envelope = vec![0, 1, 2, 3];
        let script = build_envelope_script(&small_envelope).unwrap();
        let result = parse_envelope_payload(&script).unwrap();

        assert_eq!(result, small_envelope);

        // Try with larger size
        let large_envelope = vec![1; 2000];
        let script = build_envelope_script(&large_envelope).unwrap();

        let result = parse_envelope_payload(&script).unwrap();
        assert_eq!(result, large_envelope);
    }

    #[test]
    fn test_parse_envelope_container_accepts_one_signed_leaf() {
        let pubkey = vec![0x02; SIGNED_LEAF_PUBKEY_LEN];
        let payload = vec![9; MIN_ENVELOPE_PAYLOAD_SIZE];

        let script = EnvelopeScriptBuilder::with_pubkey(&pubkey)
            .unwrap()
            .add_envelope(&payload)
            .unwrap()
            .build()
            .unwrap();
        let (extracted_pubkey, extracted_payloads) = parse_envelope_container(&script).unwrap();

        assert_eq!(extracted_pubkey, pubkey);
        assert_eq!(extracted_payloads, vec![payload]);
    }

    /// The container delegates the pubkey-length check to the strict leaf
    /// parser, so a non-32-byte key is rejected.
    #[test]
    fn test_parse_envelope_container_rejects_non_32_byte_pubkey() {
        let long_key = vec![0x03; 33];
        let payload = vec![9; MIN_ENVELOPE_PAYLOAD_SIZE];
        let script = EnvelopeScriptBuilder::with_pubkey(&long_key)
            .unwrap()
            .add_envelope(&payload)
            .unwrap()
            .build()
            .unwrap();

        assert!(matches!(
            parse_envelope_container(&script),
            Err(EnvelopeParseError::InvalidPubkeyLength { found: 33, .. })
        ));
    }

    /// The container adapter must reject the checksig bypass class on a valid
    /// 32-byte key — an `OP_NOT` that inverts the result, or a trailing
    /// `OP_DROP OP_TRUE` that discards it — since ASM checkpoint extraction calls
    /// this API.
    #[test]
    fn test_parse_envelope_container_rejects_checksig_bypass() {
        let inverted = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_NOT, OP_FALSE, OP_IF, OP_ENDIF]);
        assert!(matches!(
            parse_envelope_container(&inverted),
            Err(EnvelopeParseError::MissingOpFalse)
        ));

        let overridden =
            build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_IF, OP_ENDIF, OP_DROP, OP_TRUE]);
        assert!(matches!(
            parse_envelope_container(&overridden),
            Err(EnvelopeParseError::UnexpectedTrailingInstructions)
        ));
    }

    #[test]
    fn test_parse_envelope_missing_op_endif() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::OP_FALSE;
        use bitcoin::opcodes::all::OP_IF;

        // Build a malformed script: OP_FALSE OP_IF <data> (no OP_ENDIF)
        let malformed_script = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([1, 2, 3])
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(result, Err(EnvelopeParseError::MissingOpEndif)));
    }

    #[test]
    fn test_parse_envelope_missing_op_false() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::all::{OP_ENDIF, OP_IF};

        // Build a malformed script: OP_IF <data> OP_ENDIF (no OP_FALSE)
        let malformed_script = script::Builder::new()
            .push_opcode(OP_IF)
            .push_slice([1, 2, 3])
            .push_opcode(OP_ENDIF)
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(result, Err(EnvelopeParseError::MissingOpFalse)));
    }

    #[test]
    fn test_parse_envelope_missing_op_if() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::OP_FALSE;
        use bitcoin::opcodes::all::OP_ENDIF;

        // Build a malformed script: OP_FALSE <data> OP_ENDIF (no OP_IF)
        let malformed_script = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_slice([1, 2, 3])
            .push_opcode(OP_ENDIF)
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(result, Err(EnvelopeParseError::MissingOpIf)));
    }

    #[test]
    fn test_parse_envelope_invalid_payload_instruction() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::OP_FALSE;
        use bitcoin::opcodes::all::{OP_ADD, OP_ENDIF, OP_IF};

        // Build a malformed script with non-push instruction in payload
        let malformed_script = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([1, 2, 3])
            .push_opcode(OP_ADD) // Invalid: non-push opcode in payload
            .push_opcode(OP_ENDIF)
            .into_script();

        let result = parse_envelope_payload(&malformed_script);
        assert!(matches!(
            result,
            Err(EnvelopeParseError::UnexpectedOpcodeInPayload)
        ));
    }

    #[test]
    fn test_parse_envelope_accepts_op_false_as_empty_push() {
        use bitcoin::blockdata::script;
        use bitcoin::opcodes::OP_FALSE;
        use bitcoin::opcodes::all::{OP_ENDIF, OP_IF};

        let payload_data = [1u8, 2, 3, 4, 5];

        // OP_FALSE, OP_0, and OP_PUSHBYTES_0 all encode to 0x00 and decode as an
        // empty push, so both these constructions produce the same opener.

        // Test 1: OP_FALSE from builder (encoded as OP_PUSHBYTES_0)
        let script1 = script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(payload_data)
            .push_opcode(OP_ENDIF)
            .into_script();

        let result1 = parse_envelope_payload(&script1).unwrap();
        assert_eq!(result1, payload_data);

        // Test 2: Manually constructed with empty push bytes (same as OP_FALSE)
        let script2 = script::Builder::new()
            .push_slice([]) // Empty push = OP_FALSE
            .push_opcode(OP_IF)
            .push_slice(payload_data)
            .push_opcode(OP_ENDIF)
            .into_script();

        let result2 = parse_envelope_payload(&script2).unwrap();
        assert_eq!(result2, payload_data);

        // Both encodings decode to the same empty-push opener.
        assert_eq!(result1, result2);
    }

    // Strict signed envelope leaf parser.

    const TEST_PUBKEY: [u8; SIGNED_LEAF_PUBKEY_LEN] = [7u8; SIGNED_LEAF_PUBKEY_LEN];

    /// Builds the canonical signed leaf shape the production writer emits.
    fn build_signed_leaf(payload: &[u8]) -> ScriptBuf {
        EnvelopeScriptBuilder::with_pubkey(&TEST_PUBKEY)
            .expect("pubkey accepted")
            .add_envelope(payload)
            .expect("payload accepted")
            .build_without_min_check()
            .expect("build succeeds")
    }

    /// Builds `<pubkey> OP_CHECKSIG` followed by the given opcodes, for leaves
    /// that deviate from the strict shape after the signature prefix.
    fn build_leaf_with_opcodes(pubkey: &[u8], opcodes: &[Opcode]) -> ScriptBuf {
        let mut builder = Builder::new()
            .push_slice(PushBytesBuf::try_from(pubkey.to_vec()).expect("pubkey push"))
            .push_opcode(OP_CHECKSIG);
        for opcode in opcodes {
            builder = builder.push_opcode(*opcode);
        }
        builder.into_script()
    }

    #[test]
    fn test_strict_leaf_round_trips() {
        let payload = vec![9u8; 300];

        let leaf = parse_signed_envelope_leaf(&build_signed_leaf(&payload)).expect("valid leaf");

        assert_eq!(leaf.pubkey(), &TEST_PUBKEY);
        assert_eq!(leaf.payload(), payload);
    }

    #[test]
    fn test_strict_leaf_concatenates_multi_push_payload() {
        // 1200 bytes spans three pushes at the 520-byte element limit.
        let payload: Vec<u8> = (0..1200).map(|i| (i % 251) as u8).collect();

        let leaf = parse_signed_envelope_leaf(&build_signed_leaf(&payload)).expect("valid leaf");

        assert_eq!(leaf.payload(), payload);
    }

    /// The builder's 126-byte minimum is a writer-side efficiency rule. The
    /// read path must not inherit it: DA reveals intentionally carry smaller
    /// chunks through builders that bypass the minimum.
    #[test]
    fn test_strict_leaf_accepts_payload_below_builder_minimum() {
        let payload = vec![1u8; 5];
        assert!(payload.len() < MIN_ENVELOPE_PAYLOAD_SIZE);

        let leaf = parse_signed_envelope_leaf(&build_signed_leaf(&payload)).expect("valid leaf");

        assert_eq!(leaf.payload(), payload);
    }

    #[test]
    fn test_strict_leaf_accepts_empty_payload() {
        let leaf = parse_signed_envelope_leaf(&build_signed_leaf(&[])).expect("valid leaf");

        assert!(leaf.payload().is_empty());
    }

    /// Under BIP342 a pubkey that is neither empty nor 32 bytes is an unknown
    /// key type, for which `OP_CHECKSIG` succeeds without verifying any
    /// signature. Accepting one would void the leaf's authentication.
    #[test]
    fn test_strict_leaf_rejects_non_32_byte_pubkey() {
        for len in [0usize, 1, 31, 33, 65] {
            let script = build_leaf_with_opcodes(&vec![2u8; len], &[OP_FALSE, OP_IF, OP_ENDIF]);

            let error = parse_signed_envelope_leaf(&script)
                .expect_err("non-32-byte pubkey must be rejected");

            assert!(
                matches!(
                    error,
                    EnvelopeParseError::InvalidPubkeyLength {
                        expected: SIGNED_LEAF_PUBKEY_LEN,
                        found: got
                    } if got == len
                ),
                "pubkey length {len} produced {error:?}"
            );
        }
    }

    #[test]
    fn test_strict_leaf_accepts_exactly_32_byte_pubkey() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_IF, OP_ENDIF]);

        let leaf = parse_signed_envelope_leaf(&script).expect("32-byte pubkey accepted");

        assert_eq!(leaf.pubkey(), &TEST_PUBKEY);
    }

    #[test]
    fn test_strict_leaf_rejects_leading_opcode() {
        let script = bitcoin::blockdata::script::Builder::new()
            .push_opcode(OP_TRUE)
            .push_slice(TEST_PUBKEY)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_opcode(OP_ENDIF)
            .into_script();

        let error =
            parse_signed_envelope_leaf(&script).expect_err("leading opcode must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingPubkey));
    }

    /// A bare `OP_FALSE OP_IF ... OP_ENDIF` leaf, which the lenient parsers
    /// accept and which carries no signature commitment at all.
    #[test]
    fn test_strict_leaf_rejects_bare_envelope() {
        let script = bitcoin::blockdata::script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice([1u8, 2, 3])
            .push_opcode(OP_ENDIF)
            .into_script();

        let error =
            parse_signed_envelope_leaf(&script).expect_err("bare envelope must be rejected");

        // The empty push standing in for OP_FALSE reads as a 0-byte pubkey.
        assert!(matches!(
            error,
            EnvelopeParseError::InvalidPubkeyLength { found: 0, .. }
        ));
    }

    #[test]
    fn test_strict_leaf_rejects_missing_checksig() {
        let script = bitcoin::blockdata::script::Builder::new()
            .push_slice(TEST_PUBKEY)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_opcode(OP_ENDIF)
            .into_script();

        let error =
            parse_signed_envelope_leaf(&script).expect_err("missing checksig must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingChecksig));
    }

    /// `OP_CHECKSIG OP_NOT` inverts the check, making the leaf spendable
    /// precisely when the signature is invalid.
    #[test]
    fn test_strict_leaf_rejects_checksig_inversion() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_NOT, OP_FALSE, OP_IF, OP_ENDIF]);

        let error =
            parse_signed_envelope_leaf(&script).expect_err("checksig inversion must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingOpFalse));
    }

    /// `OP_ENDIF OP_DROP OP_TRUE` discards the signature check result.
    #[test]
    fn test_strict_leaf_rejects_checksig_override() {
        let script =
            build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_IF, OP_ENDIF, OP_DROP, OP_TRUE]);

        let error =
            parse_signed_envelope_leaf(&script).expect_err("checksig override must be rejected");

        assert!(matches!(
            error,
            EnvelopeParseError::UnexpectedTrailingInstructions
        ));
    }

    #[test]
    fn test_strict_leaf_rejects_junk_before_op_false() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_DROP, OP_FALSE, OP_IF, OP_ENDIF]);

        let error = parse_signed_envelope_leaf(&script).expect_err("junk must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingOpFalse));
    }

    #[test]
    fn test_strict_leaf_rejects_missing_op_if() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_ENDIF]);

        let error =
            parse_signed_envelope_leaf(&script).expect_err("missing OP_IF must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingOpIf));
    }

    #[test]
    fn test_strict_leaf_rejects_missing_op_endif() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_IF]);

        let error =
            parse_signed_envelope_leaf(&script).expect_err("missing OP_ENDIF must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingOpEndif));
    }

    #[test]
    fn test_strict_leaf_rejects_non_push_in_body() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_IF, OP_ADD, OP_ENDIF]);

        let error = parse_signed_envelope_leaf(&script).expect_err("body opcode must be rejected");

        assert!(matches!(
            error,
            EnvelopeParseError::UnexpectedOpcodeInPayload
        ));
    }

    #[test]
    fn test_strict_leaf_rejects_trailing_opcode() {
        let script = build_leaf_with_opcodes(&TEST_PUBKEY, &[OP_FALSE, OP_IF, OP_ENDIF, OP_TRUE]);

        let error = parse_signed_envelope_leaf(&script).expect_err("trailing op must be rejected");

        assert!(matches!(
            error,
            EnvelopeParseError::UnexpectedTrailingInstructions
        ));
    }

    /// SPS-53 allows exactly one chunk per reveal. The lenient parser returns
    /// the first envelope and silently drops the second.
    #[test]
    fn test_strict_leaf_rejects_second_envelope() {
        let script = EnvelopeScriptBuilder::with_pubkey(&TEST_PUBKEY)
            .expect("pubkey accepted")
            .add_envelope(&[1u8; 10])
            .expect("first payload accepted")
            .add_envelope(&[2u8; 10])
            .expect("second payload accepted")
            .build_without_min_check()
            .expect("build succeeds");

        let error =
            parse_signed_envelope_leaf(&script).expect_err("second envelope must be rejected");

        assert!(matches!(
            error,
            EnvelopeParseError::UnexpectedTrailingInstructions
        ));
    }

    /// The parser's own allocation bound on untrusted L1 input. It cannot be
    /// reached through `EnvelopeScriptBuilder`, which rejects an oversized
    /// payload at build time, so the script is assembled by hand.
    #[test]
    fn test_strict_leaf_rejects_payload_over_maximum() {
        let oversized = MAX_ENVELOPE_PAYLOAD_SIZE + 1;

        let mut builder = Builder::new()
            .push_slice(TEST_PUBKEY)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF);
        let mut remaining = oversized;
        while remaining > 0 {
            let chunk = remaining.min(MAX_SCRIPT_ELEMENT_SIZE);
            builder = builder.push_slice(
                PushBytesBuf::try_from(vec![0u8; chunk]).expect("chunk within push limit"),
            );
            remaining -= chunk;
        }
        let script = builder.push_opcode(OP_ENDIF).into_script();

        let error =
            parse_signed_envelope_leaf(&script).expect_err("oversized payload must be rejected");

        assert!(
            matches!(
                error,
                EnvelopeParseError::PayloadTooLarge {
                    total_size,
                    max: MAX_ENVELOPE_PAYLOAD_SIZE
                } if total_size > MAX_ENVELOPE_PAYLOAD_SIZE
            ),
            "got {error:?}"
        );
    }

    /// The bound is inclusive: a payload of exactly the maximum is valid.
    #[test]
    fn test_strict_leaf_accepts_payload_at_maximum() {
        let leaf =
            parse_signed_envelope_leaf(&build_signed_leaf(&vec![0u8; MAX_ENVELOPE_PAYLOAD_SIZE]))
                .expect("payload at maximum is valid");

        assert_eq!(leaf.payload().len(), MAX_ENVELOPE_PAYLOAD_SIZE);
    }

    #[test]
    fn test_strict_leaf_rejects_empty_script() {
        let error = parse_signed_envelope_leaf(&ScriptBuf::new())
            .expect_err("empty script must be rejected");

        assert!(matches!(error, EnvelopeParseError::MissingPubkey));
    }

    #[test]
    fn test_strict_leaf_rejects_undecodable_script() {
        // PUSHBYTES_5 with only one byte of data following it.
        let script = ScriptBuf::from_bytes(vec![0x05, 0x01]);

        let error =
            parse_signed_envelope_leaf(&script).expect_err("undecodable script must be rejected");

        assert!(matches!(error, EnvelopeParseError::MalformedScript));
    }

    /// Sharing the payload loop routes the lenient parsers through
    /// `next_instruction`, so a truncated push inside an envelope is reported
    /// as a malformed script rather than as an unexpected opcode, which it is
    /// not. Still a rejection either way.
    #[test]
    fn test_lenient_payload_reports_undecodable_push_as_malformed() {
        let mut bytes = Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .into_script()
            .to_bytes();
        // PUSHBYTES_5 announcing more data than the script carries.
        bytes.extend_from_slice(&[0x05, 0x01]);
        let script = ScriptBuf::from_bytes(bytes);

        let error = parse_envelope_payload(&script).expect_err("truncated push must be rejected");

        assert!(matches!(error, EnvelopeParseError::MalformedScript));
    }
}
