//! Typed OL log payload structs and their type-id namespace.

use strata_codec::{Codec, VarVec};
use strata_msg_fmt::TypeId;

use crate::OLLogType;

/// Maximum byte length for a withdrawal destination BOSD descriptor.
const MAX_DEST_BYTES: u32 = 255;

/// Maximum byte length for snark account update extra data.
///
/// Matches `SAU_MAX_EXTRA_DATA_BYTES` from strata's OL transaction SSZ spec. The bound is a
/// compile-time cap only; it does not affect the wire encoding (the `VarVec` length prefix encodes
/// the actual length), so an asm-side `VarVec<u8>` and this bounded alias are byte-identical.
const MAX_EXTRA_DATA_BYTES: u32 = 1024;

/// Bounded [`VarVec`] holding a withdrawal intent destination BOSD.
pub type DestinationBufVec = VarVec<u8, { MAX_DEST_BYTES }>;

/// Bounded [`VarVec`] holding SAU extra data.
pub type ExtraDataBufVec = VarVec<u8, { MAX_EXTRA_DATA_BYTES }>;

/// msg-fmt type id for [`SimpleWithdrawalIntentLogData`].
///
/// This is a **wire contract** shared by strata (producer) and asm (consumer): if this value or
/// the field layout of [`SimpleWithdrawalIntentLogData`] drifts, withdrawal intents silently vanish
/// from checkpoints (funds burned on L2, unwithdrawable on L1). This crate is the single source of
/// truth for both sides.
///
/// Note: this is a *different* namespace from the SPS-52 ASM log ids in `strata-asm-logs`; do not
/// reuse those.
pub const SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID: TypeId = 0x01;

/// msg-fmt type id for [`SnarkAccountUpdateLogData`].
pub const SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID: TypeId = 0x02;

/// Payload for a simple withdrawal intent log.
///
/// Emitted by the OL STF when a withdrawal message is processed at the bridge
/// gateway account.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
pub struct SimpleWithdrawalIntentLogData {
    /// Amount being withdrawn (sats).
    pub amt: u64,

    /// Destination BOSD.
    pub dest: DestinationBufVec,

    /// User's selected operator index for withdrawal assignment.
    // TODO(STR-1861): encode as varint to reduce DA cost in checkpoint payloads.
    pub selected_operator: u32,
}

impl SimpleWithdrawalIntentLogData {
    /// Create a new simple withdrawal intent log data instance.
    ///
    /// Returns `None` if `dest` exceeds the [`DestinationBufVec`] bound.
    pub fn new(amt: u64, dest: Vec<u8>, selected_operator: u32) -> Option<Self> {
        let dest = VarVec::from_vec(dest)?;
        Some(Self {
            amt,
            dest,
            selected_operator,
        })
    }

    /// Get the withdrawal amount.
    pub fn amt(&self) -> u64 {
        self.amt
    }

    /// Get the destination as bytes.
    pub fn dest(&self) -> &[u8] {
        self.dest.as_ref()
    }
}

impl OLLogType for SimpleWithdrawalIntentLogData {
    const LOG_TYPE_ID: TypeId = SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID;
}

/// Payload for a snark account update log.
///
/// This log is emitted when a snark account is updated through a transaction.
/// It contains the new message index (sequence number) and any extra data
/// from the update operation.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
pub struct SnarkAccountUpdateLogData {
    /// The new message index (sequence number) after the update.
    pub new_msg_idx: u64,

    /// Extra data from the update operation.
    pub extra_data: ExtraDataBufVec,
}

impl SnarkAccountUpdateLogData {
    /// Create a new snark account update log data instance.
    ///
    /// Returns `None` if `extra_data` exceeds the [`ExtraDataBufVec`] bound.
    pub fn new(new_msg_idx: u64, extra_data: Vec<u8>) -> Option<Self> {
        VarVec::from_vec(extra_data).map(|extra_data| Self {
            new_msg_idx,
            extra_data,
        })
    }

    /// Get the new message index.
    pub fn new_msg_idx(&self) -> u64 {
        self.new_msg_idx
    }

    /// Get the extra data as bytes.
    pub fn extra_data(&self) -> &[u8] {
        self.extra_data.as_ref()
    }
}

impl OLLogType for SnarkAccountUpdateLogData {
    const LOG_TYPE_ID: TypeId = SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_codec::{decode_buf_exact, encode_to_vec};
    use strata_msg_fmt::{Msg, MsgRef};

    use super::*;
    use crate::LogDecodeError;

    fn withdrawal_strategy() -> impl Strategy<Value = SimpleWithdrawalIntentLogData> {
        (
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=MAX_DEST_BYTES as usize),
            any::<u32>(),
        )
            .prop_map(|(amt, dest, selected_operator)| {
                SimpleWithdrawalIntentLogData::new(amt, dest, selected_operator)
                    .expect("dest within bounds")
            })
    }

    fn snark_update_strategy() -> impl Strategy<Value = SnarkAccountUpdateLogData> {
        (
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=MAX_EXTRA_DATA_BYTES as usize),
        )
            .prop_map(|(new_msg_idx, extra_data)| {
                SnarkAccountUpdateLogData::new(new_msg_idx, extra_data)
                    .expect("extra data within bounds")
            })
    }

    /// Byte-level conformance lock for the withdrawal-intent log envelope.
    ///
    /// This pins the exact `encode_log` output for a fixed payload so the wire contract cannot
    /// drift silently while the duplicated copies in asm/strata are being deleted during the
    /// three-repo rollout. If this assertion changes, the wire format changed: do NOT delete any
    /// downstream copy until the divergence is understood.
    #[test]
    fn test_withdrawal_log_wire_conformance() {
        let log = SimpleWithdrawalIntentLogData::new(
            0x0102_0304_0506_0708,
            b"dest".to_vec(),
            0x0a0b_0c0d,
        )
        .expect("dest within bounds");

        let envelope = log.encode_log().expect("encode_log should succeed");

        // type-id prefix (0x01) ++ codec(amt u64) ++ codec(dest VarVec) ++ codec(selected u32).
        // Integers are big-endian; the VarVec is a varint length prefix followed by its bytes.
        let expected: &[u8] = &[
            0x01, // msg-fmt type id
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // amt (BE u64)
            0x04, // dest length (varint)
            b'd', b'e', b's', b't', // dest bytes
            0x0a, 0x0b, 0x0c, 0x0d, // selected_operator (BE u32)
        ];
        assert_eq!(envelope.as_slice(), expected);
    }

    #[test]
    fn test_simple_withdrawal_intent_log_data_codec() {
        let log_data = SimpleWithdrawalIntentLogData {
            amt: 100_000_000, // 1 BTC
            dest: VarVec::from_vec(b"bc1qtest123456789".to_vec()).unwrap(),
            selected_operator: 42,
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.amt, log_data.amt);
        assert_eq!(decoded.dest.as_ref(), log_data.dest.as_ref());
        assert_eq!(decoded.selected_operator, log_data.selected_operator);
    }

    #[test]
    fn test_simple_withdrawal_intent_empty_dest() {
        let log_data = SimpleWithdrawalIntentLogData {
            amt: 50_000,
            dest: VarVec::from_vec(vec![]).unwrap(),
            selected_operator: 0,
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.amt, 50_000);
        assert!(decoded.dest.is_empty());
    }

    #[test]
    fn test_simple_withdrawal_intent_max_values() {
        let log_data = SimpleWithdrawalIntentLogData {
            amt: u64::MAX,
            dest: VarVec::from_vec(vec![255u8; 200]).unwrap(),
            selected_operator: u32::MAX,
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.amt, u64::MAX);
        assert_eq!(decoded.dest.len(), 200);
        assert_eq!(decoded.dest.as_ref(), &vec![255u8; 200][..]);
    }

    #[test]
    fn test_snark_account_update_log_data_codec() {
        let log_data = SnarkAccountUpdateLogData {
            new_msg_idx: 12345,
            extra_data: VarVec::from_vec(b"extra_test_data".to_vec()).unwrap(),
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SnarkAccountUpdateLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.new_msg_idx, log_data.new_msg_idx);
        assert_eq!(decoded.extra_data.as_ref(), log_data.extra_data.as_ref());
    }

    #[test]
    fn test_snark_account_update_max_values() {
        let log_data = SnarkAccountUpdateLogData {
            new_msg_idx: u64::MAX,
            extra_data: VarVec::from_vec(vec![255u8; 250]).unwrap(),
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SnarkAccountUpdateLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.new_msg_idx, u64::MAX);
        assert_eq!(decoded.extra_data.len(), 250);
        assert_eq!(decoded.extra_data.as_ref(), &vec![255u8; 250][..]);
    }

    #[test]
    fn test_log_envelope_round_trip() {
        let snark = SnarkAccountUpdateLogData {
            new_msg_idx: 7,
            extra_data: VarVec::from_vec(b"abc".to_vec()).unwrap(),
        };
        let encoded = snark.encode_log().unwrap();

        // Envelope carries the type id prefix.
        let msg = MsgRef::try_from(encoded.as_slice()).unwrap();
        assert_eq!(msg.ty(), SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID);

        let decoded = SnarkAccountUpdateLogData::try_decode_log(&msg).unwrap();
        assert_eq!(decoded, snark);
    }

    #[test]
    fn test_log_decode_type_mismatch() {
        let withdrawal = SimpleWithdrawalIntentLogData {
            amt: 10,
            dest: VarVec::from_vec(b"d".to_vec()).unwrap(),
            selected_operator: 1,
        };
        let encoded = withdrawal.encode_log().unwrap();
        let msg = MsgRef::try_from(encoded.as_slice()).unwrap();

        // Decoding as the wrong log type reports a type mismatch rather than a spurious decode.
        let err = SnarkAccountUpdateLogData::try_decode_log(&msg).unwrap_err();
        assert!(matches!(
            err,
            LogDecodeError::TypeMismatch {
                expected: SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID,
                found,
            } if found == SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID
        ));

        // And decoding as the right type still works.
        SimpleWithdrawalIntentLogData::try_decode_log(&msg).unwrap();
    }

    proptest! {
        #[test]
        fn test_withdrawal_log_envelope_round_trip(log_data in withdrawal_strategy()) {
            let encoded = log_data.encode_log().expect("encode_log should succeed");

            let msg = MsgRef::try_from(encoded.as_slice()).expect("envelope should parse");
            prop_assert_eq!(msg.ty(), SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID);

            let decoded = SimpleWithdrawalIntentLogData::try_decode_log(&msg)
                .expect("try_decode_log should succeed");
            prop_assert_eq!(decoded, log_data);
        }

        #[test]
        fn test_snark_update_log_envelope_round_trip(log_data in snark_update_strategy()) {
            let encoded = log_data.encode_log().expect("encode_log should succeed");

            let msg = MsgRef::try_from(encoded.as_slice()).expect("envelope should parse");
            prop_assert_eq!(msg.ty(), SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID);

            let decoded = SnarkAccountUpdateLogData::try_decode_log(&msg)
                .expect("try_decode_log should succeed");
            prop_assert_eq!(decoded, log_data);
        }

        /// Decoding a withdrawal envelope as a snark update (and vice versa) reports a type
        /// mismatch rather than a spurious decode.
        #[test]
        fn test_withdrawal_log_decode_type_mismatch(log_data in withdrawal_strategy()) {
            let encoded = log_data.encode_log().expect("encode_log should succeed");
            let msg = MsgRef::try_from(encoded.as_slice()).expect("envelope should parse");

            let err = SnarkAccountUpdateLogData::try_decode_log(&msg)
                .expect_err("decoding as the wrong type should fail");
            let is_expected_mismatch = matches!(
                err,
                LogDecodeError::TypeMismatch {
                    expected: SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID,
                    found,
                } if found == SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID
            );
            prop_assert!(is_expected_mismatch);
        }

        #[test]
        fn test_snark_update_log_decode_type_mismatch(log_data in snark_update_strategy()) {
            let encoded = log_data.encode_log().expect("encode_log should succeed");
            let msg = MsgRef::try_from(encoded.as_slice()).expect("envelope should parse");

            let err = SimpleWithdrawalIntentLogData::try_decode_log(&msg)
                .expect_err("decoding as the wrong type should fail");
            let is_expected_mismatch = matches!(
                err,
                LogDecodeError::TypeMismatch {
                    expected: SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID,
                    found,
                } if found == SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID
            );
            prop_assert!(is_expected_mismatch);
        }
    }
}
