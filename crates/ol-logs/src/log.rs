//! The [`OLLog`] checkpoint log-entry container and its envelope helpers.

use ssz_types::VariableList;
use strata_codec::CodecError;
use strata_identifiers::{AccountSerial, Buf32};
use strata_msg_fmt::{Msg, MsgRef, TypeId};
use tree_hash::{Sha256Hasher, TreeHash};

pub use crate::ssz_generated::ssz::log::{MAX_LOG_PAYLOAD_LEN, OLLog, OLLogRef};
use crate::{LogDecodeError, OLLogType};

impl OLLog {
    /// Creates a log entry from a raw payload.
    ///
    /// Panics if `payload` exceeds [`MAX_LOG_PAYLOAD_LEN`]. Use [`OLLog::from_log`] to build one
    /// from a typed payload via the msg-fmt envelope.
    pub fn new(account_serial: AccountSerial, payload: Vec<u8>) -> Self {
        Self {
            account_serial,
            payload: VariableList::new(payload).expect("ol log: payload too large"),
        }
    }

    /// The account serial this log relates to.
    pub fn account_serial(&self) -> AccountSerial {
        self.account_serial
    }

    /// The raw payload bytes (a msg-fmt envelope).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Builds a log whose payload is the msg-fmt envelope for a typed OL log.
    ///
    /// The payload is `TypeId(T::LOG_TYPE_ID) ++ codec(log)`, so consumers dispatch on the log type
    /// via [`OLLog::try_into_log`].
    pub fn from_log<T: OLLogType>(
        account_serial: AccountSerial,
        log: &T,
    ) -> Result<Self, CodecError> {
        Ok(Self::new(account_serial, log.encode_log()?))
    }

    /// Interprets the payload as a msg-fmt message, if it is a valid envelope.
    pub fn try_as_msg(&self) -> Option<MsgRef<'_>> {
        MsgRef::try_from(self.payload()).ok()
    }

    /// The envelope type id, if the payload is a valid msg-fmt message.
    pub fn ty(&self) -> Option<TypeId> {
        self.try_as_msg().map(|msg| msg.ty())
    }

    /// Decodes the payload as a specific typed OL log.
    ///
    /// Parses the msg-fmt envelope, checks the type id matches `T::LOG_TYPE_ID`, and decodes the
    /// body — returning [`LogDecodeError::TypeMismatch`] when the envelope carries a different log
    /// type.
    pub fn try_into_log<T: OLLogType>(&self) -> Result<T, LogDecodeError> {
        T::decode_log(self.payload())
    }

    /// Computes the SSZ tree-hash commitment of this log.
    pub fn compute_hash_commitment(&self) -> Buf32 {
        let root = TreeHash::tree_hash_root::<Sha256Hasher>(self);
        Buf32::from(root.0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{SimpleWithdrawalIntentLogData, SnarkAccountUpdateLogData};

    fn serial_strategy() -> impl Strategy<Value = AccountSerial> {
        any::<u32>().prop_map(AccountSerial::new)
    }

    fn withdrawal_strategy() -> impl Strategy<Value = SimpleWithdrawalIntentLogData> {
        // `dest` is bounded so the encoded envelope stays within `MAX_LOG_PAYLOAD_LEN`.
        (
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=255usize),
            any::<u32>(),
        )
            .prop_map(|(amt, dest, selected_operator)| {
                SimpleWithdrawalIntentLogData::new(amt, dest, selected_operator)
                    .expect("dest within bounds")
            })
    }

    fn snark_strategy() -> impl Strategy<Value = SnarkAccountUpdateLogData> {
        // `extra_data` is bounded so the encoded envelope stays within `MAX_LOG_PAYLOAD_LEN`.
        (
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=400usize),
        )
            .prop_map(|(new_msg_idx, extra_data)| {
                SnarkAccountUpdateLogData::new(new_msg_idx, extra_data)
                    .expect("extra within bounds")
            })
    }

    proptest! {
        #[test]
        fn from_log_round_trips_withdrawal(
            serial in serial_strategy(),
            payload in withdrawal_strategy(),
        ) {
            let log = OLLog::from_log(serial, &payload).expect("from_log should succeed");

            prop_assert_eq!(log.account_serial(), serial);
            prop_assert_eq!(log.ty(), Some(SimpleWithdrawalIntentLogData::LOG_TYPE_ID));

            let decoded: SimpleWithdrawalIntentLogData =
                log.try_into_log().expect("try_into_log should succeed");
            prop_assert_eq!(decoded, payload);
        }

        #[test]
        fn from_log_round_trips_snark(
            serial in serial_strategy(),
            payload in snark_strategy(),
        ) {
            let log = OLLog::from_log(serial, &payload).expect("from_log should succeed");

            prop_assert_eq!(log.account_serial(), serial);
            prop_assert_eq!(log.ty(), Some(SnarkAccountUpdateLogData::LOG_TYPE_ID));

            let decoded: SnarkAccountUpdateLogData =
                log.try_into_log().expect("try_into_log should succeed");
            prop_assert_eq!(decoded, payload);
        }

        /// Decoding a log as the wrong typed payload reports an error rather than succeeding.
        #[test]
        fn try_into_log_wrong_type_fails(
            serial in serial_strategy(),
            payload in withdrawal_strategy(),
        ) {
            let log = OLLog::from_log(serial, &payload).expect("from_log should succeed");
            prop_assert!(log.try_into_log::<SnarkAccountUpdateLogData>().is_err());
        }

        #[test]
        fn hash_commitment_matches_for_equal_logs(
            serial in serial_strategy(),
            bytes in prop::collection::vec(any::<u8>(), 0..=MAX_LOG_PAYLOAD_LEN as usize),
        ) {
            let a = OLLog::new(serial, bytes.clone());
            let b = OLLog::new(serial, bytes);
            prop_assert_eq!(a.compute_hash_commitment(), b.compute_hash_commitment());
        }
    }
}
