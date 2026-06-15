//! Shared orchestration-layer (OL) log payload types.
//!
//! OL log payload layer carried in checkpoint sidecars: the typed payload structs
//! ([`SimpleWithdrawalIntentLogData`], [`SnarkAccountUpdateLogData`]), their type-id namespace, the
//! [`OLLogType`] envelope codec, [`LogDecodeError`], and the [`decode_typed_logs`] filter/decode
//! helper.

#[allow(unreachable_pub, missing_docs, reason = "generated code")]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_ssz.rs"));
}

mod envelope;
mod log;
mod payloads;

pub use envelope::{LogDecodeError, OLLogType, decode_typed_logs};
pub use log::{MAX_LOG_PAYLOAD_LEN, OLLog, OLLogRef};
pub use payloads::{
    DestinationBufVec, ExtraDataBufVec, SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID,
    SNARK_ACCOUNT_UPDATE_LOG_TYPE_ID, SimpleWithdrawalIntentLogData, SnarkAccountUpdateLogData,
};
