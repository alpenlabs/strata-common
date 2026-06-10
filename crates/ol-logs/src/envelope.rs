//! Envelope codec and typed dispatch for OL log payloads.

use std::iter;

use strata_codec::{Codec, CodecError, decode_buf_exact};
use strata_identifiers::AccountSerial;
use strata_msg_fmt::{self as msg_fmt, Msg, MsgRef, TypeId, try_encode_into_buf};

use crate::OLLog;

/// Error decoding a typed OL log payload from its `strata_msg_fmt` envelope.
///
/// The variants reconcile the two former per-repo error types into one superset: asm's
/// `OLLogDecodeError` (which surfaced envelope-parse failures via `Envelope`) and strata's
/// 2-variant `LogDecodeError` (which did not).
#[derive(Debug, thiserror::Error)]
pub enum LogDecodeError {
    /// The envelope's type id did not match the requested log type.
    #[error("ol log type mismatch: expected {expected}, found {found}")]
    TypeMismatch {
        /// Type id requested by the caller.
        expected: TypeId,
        /// Type id found in the envelope.
        found: TypeId,
    },

    /// Failed to decode the log body via the codec.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),

    /// Failed to parse the msg-fmt envelope.
    #[error("msgfmt: {0:?}")]
    Envelope(#[from] msg_fmt::Error),
}

/// A typed orchestration-layer log payload.
///
/// Each impl carries a [`TypeId`] tagging it within an OL log payload, encoded as a
/// `strata_msg_fmt` envelope (type prefix + codec body). Consumers parse the payload once and
/// dispatch on the type id rather than guessing the concrete type from raw bytes.
pub trait OLLogType: Codec + Sized {
    /// The msg-fmt type id identifying this log payload.
    const LOG_TYPE_ID: TypeId;

    /// Encodes this payload into a msg-fmt envelope (type prefix followed by the codec body).
    fn encode_log(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        // Write the msg-fmt type prefix, then encode the body directly into the same buffer to
        // avoid a separate allocation and copy of the body.
        try_encode_into_buf(Self::LOG_TYPE_ID, iter::empty(), &mut buf)
            .expect("ol log: type id must be within msg-fmt bounds");
        self.encode(&mut buf)?;
        Ok(buf)
    }

    /// Decodes this payload from an already-parsed msg-fmt message.
    ///
    /// Returns [`LogDecodeError::TypeMismatch`] if the message's type id does not match
    /// [`Self::LOG_TYPE_ID`], or [`LogDecodeError::Codec`] if the body fails to decode.
    fn try_decode_log(msg: &MsgRef<'_>) -> Result<Self, LogDecodeError> {
        let found = msg.ty();
        if found != Self::LOG_TYPE_ID {
            return Err(LogDecodeError::TypeMismatch {
                expected: Self::LOG_TYPE_ID,
                found,
            });
        }
        Ok(decode_buf_exact(msg.body())?)
    }

    /// Decodes this payload directly from raw envelope bytes.
    ///
    /// Parses the msg-fmt envelope (surfacing [`LogDecodeError::Envelope`] on a malformed
    /// envelope) and then delegates to [`Self::try_decode_log`]. This is the convenience asm's
    /// inherent `OLLog::try_into_log` is reimplemented on top of.
    fn decode_log(payload: &[u8]) -> Result<Self, LogDecodeError> {
        let msg = MsgRef::try_from(payload)?;
        Self::try_decode_log(&msg)
    }
}

/// Filters and decodes typed OL log payloads from a slice of [`OLLog`] entries.
///
/// Yields successfully-decoded payloads of type `T`, skipping entries that don't match the optional
/// `account_guard`, don't carry `T`'s type id, or whose envelope/body fails to decode. This is the
/// shared "filter by type id (+ optional emitting account), decode the envelope body" pattern used
/// by both asm's checkpoint verifier and strata's checkpoint consumers; the caller applies any
/// further domain mapping (and hard-erroring) to the yielded payloads.
pub fn decode_typed_logs<'a, T: OLLogType>(
    logs: &'a [OLLog],
    account_guard: Option<AccountSerial>,
) -> impl Iterator<Item = T> + 'a {
    logs.iter().filter_map(move |log| {
        if account_guard.is_some_and(|guard| guard != log.account_serial()) {
            return None;
        }
        T::decode_log(log.payload()).ok()
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{SimpleWithdrawalIntentLogData, SnarkAccountUpdateLogData};

    /// One of the accounts logs are generated from; `BRIDGE` is the one the guard filters for.
    const BRIDGE: AccountSerial = AccountSerial::one();

    /// A generated log entry, tagged with how `decode_typed_logs::<SimpleWithdrawalIntentLogData>`
    /// should treat it so the expected output can be computed independently of the implementation.
    #[derive(Debug, Clone)]
    enum Entry {
        /// A well-formed withdrawal envelope — kept iff it passes the account guard.
        Withdrawal(AccountSerial, SimpleWithdrawalIntentLogData),
        /// A well-formed snark envelope — always dropped (wrong type id).
        Snark(AccountSerial, SnarkAccountUpdateLogData),
        /// An empty payload — always dropped (not a valid envelope).
        Empty(AccountSerial),
    }

    impl Entry {
        fn to_log(&self) -> OLLog {
            match self {
                Entry::Withdrawal(serial, w) => OLLog::from_log(*serial, w).unwrap(),
                Entry::Snark(serial, s) => OLLog::from_log(*serial, s).unwrap(),
                Entry::Empty(serial) => OLLog::new(*serial, Vec::new()),
            }
        }
    }

    fn account_strategy() -> impl Strategy<Value = AccountSerial> {
        prop::sample::select(vec![
            AccountSerial::zero(),
            AccountSerial::one(),
            AccountSerial::new(2),
        ])
    }

    fn withdrawal_strategy() -> impl Strategy<Value = SimpleWithdrawalIntentLogData> {
        // Bounded so the encoded envelope stays within `MAX_LOG_PAYLOAD_LEN`.
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
        (
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=400usize),
        )
            .prop_map(|(new_msg_idx, extra_data)| {
                SnarkAccountUpdateLogData::new(new_msg_idx, extra_data)
                    .expect("extra within bounds")
            })
    }

    fn entry_strategy() -> impl Strategy<Value = Entry> {
        prop_oneof![
            (account_strategy(), withdrawal_strategy())
                .prop_map(|(serial, w)| Entry::Withdrawal(serial, w)),
            (account_strategy(), snark_strategy()).prop_map(|(serial, s)| Entry::Snark(serial, s)),
            account_strategy().prop_map(Entry::Empty),
        ]
    }

    proptest! {
        /// With a guard, only well-formed withdrawal logs from the guard account survive, in order.
        #[test]
        fn decode_typed_logs_respects_type_and_account_guard(
            entries in prop::collection::vec(entry_strategy(), 0..16),
        ) {
            let logs: Vec<OLLog> = entries.iter().map(Entry::to_log).collect();

            let expected: Vec<SimpleWithdrawalIntentLogData> = entries
                .iter()
                .filter_map(|e| match e {
                    Entry::Withdrawal(serial, w) if *serial == BRIDGE => Some(w.clone()),
                    _ => None,
                })
                .collect();

            let actual: Vec<SimpleWithdrawalIntentLogData> =
                decode_typed_logs(&logs, Some(BRIDGE)).collect();

            prop_assert_eq!(actual, expected);
        }

        /// Without a guard, every well-formed withdrawal log survives regardless of account.
        #[test]
        fn decode_typed_logs_without_guard_keeps_all_withdrawals(
            entries in prop::collection::vec(entry_strategy(), 0..16),
        ) {
            let logs: Vec<OLLog> = entries.iter().map(Entry::to_log).collect();

            let expected: Vec<SimpleWithdrawalIntentLogData> = entries
                .iter()
                .filter_map(|e| match e {
                    Entry::Withdrawal(_, w) => Some(w.clone()),
                    _ => None,
                })
                .collect();

            let actual: Vec<SimpleWithdrawalIntentLogData> =
                decode_typed_logs(&logs, None).collect();

            prop_assert_eq!(actual, expected);
        }
    }
}
