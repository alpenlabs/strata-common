use std::fmt::{self, Debug, Display};
use std::ops;

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{deserialize, encode, serialize};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, AddressType, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use ssz::DecodeError;
use ssz_derive::{Decode, Encode};
use strata_codec::{Codec, CodecError, Decoder, Encoder};
use strata_identifiers::{Buf32, SszDelegate, impl_ssz_transparent_wrapper, impl_ssz_via_delegate};

use crate::ParseError;
use crate::ssz_generated::ssz::btc::{
    BitcoinOutPointSsz, BitcoinScriptSsz, BitcoinTxOutSsz, MAX_SCRIPT_SIZE,
};

const HASH_SIZE: usize = 32;
const BITCOIN_TXID_LEN: usize = 32;

/// Validates that a Bitcoin script fits within the SSZ-encodable bound
/// (`MAX_SCRIPT_SIZE`).
///
/// This is the single chokepoint enforced by every fallible constructor and
/// deserialization path of [`BitcoinTxOut`] and [`BitcoinScriptBuf`], so that an
/// instance can never hold a script that would overflow the SSZ `script_pubkey`
/// list and panic during encoding/tree-hashing.
fn check_script_size(len: usize) -> Result<(), ParseError> {
    let max = MAX_SCRIPT_SIZE as usize;
    if len > max {
        Err(ParseError::ScriptTooLarge { size: len, max })
    } else {
        Ok(())
    }
}

/// L1 output reference.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct BitcoinOutPoint(pub OutPoint);

// SSZ encoding delegates to the generated [`BitcoinOutPointSsz`] container, which
// lays the fixed-size `txid` and `vout` out per the SSZ spec — correct by
// construction rather than hand-rolled.
impl SszDelegate for BitcoinOutPoint {
    type Delegate = BitcoinOutPointSsz;

    fn into_delegate(self) -> Self::Delegate {
        BitcoinOutPointSsz {
            txid: self.0.txid.to_byte_array().into(),
            vout: self.0.vout,
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self(OutPoint {
            txid: Txid::from_byte_array(delegate.txid.0),
            vout: delegate.vout,
        }))
    }
}

impl_ssz_via_delegate!(BitcoinOutPoint);

impl From<OutPoint> for BitcoinOutPoint {
    fn from(value: OutPoint) -> Self {
        Self(value)
    }
}

impl BitcoinOutPoint {
    /// Creates a new outpoint from a transaction ID and output index.
    pub fn new(txid: Txid, vout: u32) -> Self {
        Self(OutPoint::new(txid, vout))
    }

    /// Returns a reference to the inner [`OutPoint`].
    pub fn outpoint(&self) -> &OutPoint {
        &self.0
    }
}

// Implement Arbitrary for the wrapper
impl<'a> Arbitrary<'a> for BitcoinOutPoint {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a random 32-byte array for the transaction ID (txid)
        let mut txid_bytes = [0u8; HASH_SIZE];
        u.fill_buffer(&mut txid_bytes)?;
        let txid_bytes = &txid_bytes[..];
        let hash = sha256d::Hash::from_slice(txid_bytes).unwrap();
        let txid = bitcoin::Txid::from_slice(&hash[..]).unwrap();

        // Generate a random 4-byte integer for the output index (vout)
        let vout = u.int_in_range(0..=u32::MAX)?;

        Ok(BitcoinOutPoint(OutPoint { txid, vout }))
    }
}
/// Validates that an amount does not exceed the bitcoin money supply
/// ([`Amount::MAX_MONEY`]).
///
/// This is the single chokepoint enforced by every fallible constructor and
/// deserialization path of [`BitcoinAmount`], so that an instance can never hold
/// a value beyond the money supply.
fn check_amount(sats: u64) -> Result<(), ParseError> {
    if sats > Amount::MAX_MONEY.to_sat() {
        Err(ParseError::AmountTooLarge { sats })
    } else {
        Ok(())
    }
}

/// A wrapper around [`bitcoin::Amount`] that adds the trait impls the upstream
/// type lacks ([`Arbitrary`], SSZ, and [`Codec`]).
///
/// Every path that parses untrusted input — the `TryFrom<u64>` constructor and
/// all deserialization paths — routes through `check_amount`, rejecting values
/// above [`Amount::MAX_MONEY`]. Wrapping an already-typed [`Amount`] via [`From`]
/// is infallible and trusts the caller.
///
/// [`Display`] and [`Debug`] are inherited from [`Amount`], so an amount prints
/// in BTC (`Display`) and as `<n> SAT` (`Debug`). SSZ encoding delegates to a
/// `u64` count of satoshis.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BitcoinAmount(Amount);

impl Display for BitcoinAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl From<Amount> for BitcoinAmount {
    fn from(value: Amount) -> Self {
        Self(value)
    }
}

impl TryFrom<u64> for BitcoinAmount {
    type Error = ParseError;

    /// Builds an amount from a satoshi count, rejecting values above
    /// [`Amount::MAX_MONEY`].
    fn try_from(sats: u64) -> Result<Self, Self::Error> {
        check_amount(sats)?;
        Ok(Self(Amount::from_sat(sats)))
    }
}

impl From<BitcoinAmount> for Amount {
    fn from(value: BitcoinAmount) -> Self {
        value.0
    }
}

impl From<BitcoinAmount> for u64 {
    fn from(value: BitcoinAmount) -> Self {
        value.to_sat()
    }
}

/// Routes through the fallible `TryFrom<u64>` constructor so the `MAX_MONEY`
/// invariant holds for deserialized (untrusted) values.
impl<'de> Deserialize<'de> for BitcoinAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let amount = Amount::deserialize(deserializer)?;
        Self::try_from(amount.to_sat()).map_err(serde::de::Error::custom)
    }
}

impl ops::Deref for BitcoinAmount {
    type Target = Amount;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for BitcoinAmount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> Arbitrary<'a> for BitcoinAmount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate only in-range values so the `MAX_MONEY` invariant holds.
        let sats = u.int_in_range(0..=Amount::MAX_MONEY.to_sat())?;
        Ok(Self(Amount::from_sat(sats)))
    }
}

impl Codec for BitcoinAmount {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let sats = u64::decode(dec)?;
        Self::try_from(sats).map_err(|_| CodecError::OobInteger)
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        self.to_sat().encode(enc)
    }
}

impl SszDelegate for BitcoinAmount {
    type Delegate = u64;

    fn into_delegate(self) -> u64 {
        self.to_sat()
    }

    fn from_delegate(delegate: u64) -> Result<Self, DecodeError> {
        Self::try_from(delegate).map_err(|e| DecodeError::BytesInvalid(e.to_string()))
    }
}

impl_ssz_via_delegate!(BitcoinAmount);

/// A Bitcoin [`Txid`] with the serialization traits used by Strata.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinTxid(Txid);

// Delegates SSZ encoding to the upstream `[u8; 32]` impl so the layout is correct
// by construction (a single fixed-size byte vector) rather than hand-rolled.
impl SszDelegate for BitcoinTxid {
    type Delegate = [u8; BITCOIN_TXID_LEN];

    fn into_delegate(self) -> Self::Delegate {
        self.0.to_byte_array()
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self(Txid::from_byte_array(delegate)))
    }
}

impl_ssz_via_delegate!(BitcoinTxid);

impl From<Txid> for BitcoinTxid {
    fn from(value: Txid) -> Self {
        Self(value)
    }
}

impl From<BitcoinTxid> for Txid {
    fn from(value: BitcoinTxid) -> Self {
        value.0
    }
}

impl BitcoinTxid {
    /// Creates a new [`BitcoinTxid`] from a [`Txid`].
    ///
    /// # Notes
    ///
    /// [`Txid`] is [`Copy`].
    pub fn new(txid: &Txid) -> Self {
        BitcoinTxid(*txid)
    }

    /// Gets the inner Bitcoin [`Txid`]
    pub fn inner(&self) -> Txid {
        self.0
    }

    /// Gets the inner Bitcoin [`Txid`] as raw bytes [`Buf32`].
    pub fn inner_raw(&self) -> Buf32 {
        self.0.as_raw_hash().to_byte_array().into()
    }
}

impl<'a> Arbitrary<'a> for BitcoinTxid {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let value = Buf32::arbitrary(u)?;
        let txid = Txid::from_byte_array(value.0);

        Ok(Self(txid))
    }
}

/// A wrapper around [`bitcoin::TxOut`] that implements some additional traits.
///
/// The wrapped script is guaranteed to be at most `MAX_SCRIPT_SIZE` bytes: every
/// constructor and deserialization path routes through `check_script_size`, so
/// the SSZ encoding below can never overflow its `script_pubkey` list.
///
/// Note: [`Deserialize`] is implemented manually to enforce that invariant on
/// deserialized values, mirroring the fallible `TryFrom<TxOut>` constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitcoinTxOut(TxOut);

/// [`Deserialize`] routes through [`BitcoinTxOut::try_from`] so the
/// `MAX_SCRIPT_SIZE` invariant holds for deserialized values.
impl<'de> Deserialize<'de> for BitcoinTxOut {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tx_out = TxOut::deserialize(deserializer)?;
        Self::try_from(tx_out).map_err(serde::de::Error::custom)
    }
}

// SSZ encoding delegates to the generated [`BitcoinTxOutSsz`] container, which
// lays out the fixed-size `value` and the length-bounded `script_pubkey`
// (`List[byte, MAX_SCRIPT_SIZE]`) per the SSZ spec. The script bound is enforced
// by the generated `VariableList` type rather than a hand-written impl.
impl SszDelegate for BitcoinTxOut {
    type Delegate = BitcoinTxOutSsz;

    fn into_delegate(self) -> Self::Delegate {
        BitcoinTxOutSsz {
            value: self.0.value.to_sat(),
            // Cannot fail: every construction/deserialization path validates the
            // script against `MAX_SCRIPT_SIZE` via `check_script_size`.
            script_pubkey: self
                .0
                .script_pubkey
                .to_bytes()
                .try_into()
                .expect("scriptPubKey exceeds MAX_SCRIPT_SIZE"),
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self(TxOut {
            value: Amount::from_sat(delegate.value),
            script_pubkey: ScriptBuf::from(delegate.script_pubkey.to_vec()),
        }))
    }
}

impl_ssz_via_delegate!(BitcoinTxOut);

impl BitcoinTxOut {
    /// Returns a reference to the inner [`TxOut`].
    pub fn inner(&self) -> &TxOut {
        &self.0
    }
}

impl TryFrom<TxOut> for BitcoinTxOut {
    type Error = ParseError;

    /// Wraps a [`TxOut`], rejecting outputs whose `script_pubkey` exceeds
    /// `MAX_SCRIPT_SIZE` so the wrapper's SSZ encoding can never panic.
    fn try_from(value: TxOut) -> Result<Self, Self::Error> {
        check_script_size(value.script_pubkey.len())?;
        Ok(Self(value))
    }
}

impl From<BitcoinTxOut> for TxOut {
    fn from(value: BitcoinTxOut) -> Self {
        value.0
    }
}

/// Implement Arbitrary for ArbitraryTxOut
impl<'a> Arbitrary<'a> for BitcoinTxOut {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate arbitrary value and script for the TxOut
        let value = u64::arbitrary(u)?;
        let script_len = usize::arbitrary(u)? % 100; // Limit script length
        let script_bytes = u.bytes(script_len)?;
        let script_pubkey = ScriptBuf::from(script_bytes.to_vec());

        Ok(Self(TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }))
    }
}

/// A wrapper around [`Buf32`] for XOnly Schnorr taproot pubkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct BitcoinXOnlyPublicKey(Buf32);

impl BitcoinXOnlyPublicKey {
    /// Construct a new [`BitcoinXOnlyPublicKey`] directly from a [`Buf32`].
    pub fn new(val: Buf32) -> Result<Self, ParseError> {
        if Self::is_valid_xonly_public_key(&val) {
            Ok(Self(val))
        } else {
            Err(ParseError::InvalidPoint(val))
        }
    }

    /// Get the underlying [`Buf32`].
    pub fn inner(&self) -> &Buf32 {
        &self.0
    }

    /// Convert a [`Address`] into a [`BitcoinXOnlyPublicKey`].
    pub fn from_address(checked_addr: &Address) -> Result<Self, ParseError> {
        if let Some(AddressType::P2tr) = checked_addr.address_type() {
            let script_pubkey = checked_addr.script_pubkey();

            // skip the version and length bytes
            let pubkey_bytes = &script_pubkey.as_bytes()[2..34];
            let output_key: XOnlyPublicKey = XOnlyPublicKey::from_slice(pubkey_bytes)?;

            Ok(Self(Buf32(output_key.serialize())))
        } else {
            Err(ParseError::UnsupportedAddress(checked_addr.address_type()))
        }
    }

    /// Convert the [`BitcoinXOnlyPublicKey`] to a `rust-bitcoin`'s [`XOnlyPublicKey`].
    pub fn to_xonly_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(self.0.as_bytes()).expect("BitcoinXOnlyPublicKey is valid")
    }

    /// Convert the [`BitcoinXOnlyPublicKey`] to an [`Address`].
    pub fn to_p2tr_address(&self, network: Network) -> Result<Address, ParseError> {
        let buf: [u8; 32] = self.0.0;
        let pubkey = XOnlyPublicKey::from_slice(&buf)?;

        Ok(Address::p2tr_tweaked(
            pubkey.dangerous_assume_tweaked(),
            network,
        ))
    }

    /// Converts [`BitcoinXOnlyPublicKey`] to [`Descriptor`].
    pub fn to_descriptor(&self) -> Result<Descriptor, ParseError> {
        Descriptor::new_p2tr(&self.to_xonly_public_key().serialize())
            .map_err(|_| ParseError::InvalidPoint(self.0))
    }

    /// Checks if the [`Buf32`] is a valid [`XOnlyPublicKey`].
    fn is_valid_xonly_public_key(buf: &Buf32) -> bool {
        XOnlyPublicKey::from_slice(buf.as_bytes()).is_ok()
    }
}

impl From<XOnlyPublicKey> for BitcoinXOnlyPublicKey {
    fn from(value: XOnlyPublicKey) -> Self {
        Self(Buf32(value.serialize()))
    }
}

impl TryFrom<BitcoinXOnlyPublicKey> for Descriptor {
    type Error = ParseError;

    fn try_from(value: BitcoinXOnlyPublicKey) -> Result<Self, Self::Error> {
        value.to_descriptor()
    }
}

impl_ssz_transparent_wrapper!(BitcoinXOnlyPublicKey, Buf32);

/// Represents a raw, byte-encoded Bitcoin transaction with custom [`Arbitrary`] support.
/// Provides conversions (via [`TryFrom`]) to and from [`Transaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct RawBitcoinTx(Vec<u8>);

impl RawBitcoinTx {
    /// Creates a new `RawBitcoinTx` from a raw byte vector.
    pub fn from_raw_bytes(bytes: Vec<u8>) -> Self {
        RawBitcoinTx(bytes)
    }

    /// Returns the raw serialized transaction bytes.
    pub fn as_raw_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the raw serialized transaction bytes.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Transaction> for RawBitcoinTx {
    fn from(value: Transaction) -> Self {
        Self(serialize(&value))
    }
}

impl TryFrom<RawBitcoinTx> for Transaction {
    type Error = encode::Error;
    fn try_from(value: RawBitcoinTx) -> Result<Self, Self::Error> {
        deserialize(&value.0)
    }
}

impl TryFrom<&RawBitcoinTx> for Transaction {
    type Error = encode::Error;
    fn try_from(value: &RawBitcoinTx) -> Result<Self, Self::Error> {
        deserialize(&value.0)
    }
}

impl<'a> arbitrary::Arbitrary<'a> for RawBitcoinTx {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Random number of inputs and outputs (bounded for simplicity)
        let input_count = u.int_in_range::<usize>(0..=4)?;
        let output_count = u.int_in_range::<usize>(0..=4)?;

        // Build random inputs
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            // Random 32-byte TXID
            let mut txid_bytes = [0u8; 32];
            u.fill_buffer(&mut txid_bytes)?;

            // Random vout
            let vout = u32::arbitrary(u)?;

            // Random scriptSig (bounded size)
            let script_sig_size = u.int_in_range::<usize>(0..=50)?;
            let script_sig_bytes = u.bytes(script_sig_size)?;
            let script_sig = ScriptBuf::from_bytes(script_sig_bytes.to_vec());

            inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(txid_bytes),
                    vout,
                },
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::default(), // or generate random witness if desired
            });
        }

        // Build random outputs
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            // Random value (in satoshis)
            let value = Amount::from_sat(u64::arbitrary(u)?);

            // Random scriptPubKey (bounded size)
            let script_pubkey_size = u.int_in_range::<usize>(0..=50)?;
            let script_pubkey_bytes = u.bytes(script_pubkey_size)?;
            let script_pubkey = ScriptBuf::from(script_pubkey_bytes.to_vec());

            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }

        // Construct the transaction
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        Ok(tx.into())
    }
}

/// SSZ-compatible wrapper around Bitcoin's [`ScriptBuf`].
///
/// The wrapped script is guaranteed to be at most `MAX_SCRIPT_SIZE` bytes: every
/// constructor and deserialization path routes through `check_script_size`, so
/// the SSZ encoding below can never overflow its byte list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinScriptBuf(ScriptBuf);

// SSZ encoding delegates to [`BitcoinScriptSsz`] (`List[byte, MAX_SCRIPT_SIZE]`),
// the generated length-bounded byte list, so the layout and bound are correct by
// construction rather than hand-rolled.
impl SszDelegate for BitcoinScriptBuf {
    type Delegate = BitcoinScriptSsz;

    fn into_delegate(self) -> Self::Delegate {
        // Cannot fail: every construction/deserialization path validates the
        // script against `MAX_SCRIPT_SIZE` via `check_script_size`.
        self.0
            .to_bytes()
            .try_into()
            .expect("script exceeds MAX_SCRIPT_SIZE")
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        Ok(Self(ScriptBuf::from(delegate.to_vec())))
    }
}

impl_ssz_via_delegate!(BitcoinScriptBuf);

impl BitcoinScriptBuf {
    /// Returns a reference to the inner [`ScriptBuf`].
    pub fn inner(&self) -> &ScriptBuf {
        &self.0
    }
}

impl TryFrom<ScriptBuf> for BitcoinScriptBuf {
    type Error = ParseError;

    /// Wraps a [`ScriptBuf`], rejecting scripts that exceed `MAX_SCRIPT_SIZE` so
    /// the wrapper's SSZ encoding can never panic.
    fn try_from(value: ScriptBuf) -> Result<Self, Self::Error> {
        check_script_size(value.len())?;
        Ok(Self(value))
    }
}

impl<'a> Arbitrary<'a> for BitcoinScriptBuf {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate arbitrary script
        let script_len = usize::arbitrary(u)? % 100; // Limit script length
        let script_bytes = u.bytes(script_len)?;
        let script = ScriptBuf::from(script_bytes.to_vec());

        Ok(Self(script))
    }
}

#[cfg(test)]
mod tests {

    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
    use bitcoin_bosd::DescriptorType;
    use proptest::prelude::*;
    use ssz::{Decode, Encode};
    use strata_identifiers::Buf32;
    use strata_ssz_tests::ssz_proptest;

    use super::{
        BitcoinAmount, BitcoinOutPoint, BitcoinScriptBuf, BitcoinTxOut, BitcoinTxid,
        BitcoinXOnlyPublicKey, MAX_SCRIPT_SIZE, RawBitcoinTx,
    };
    use crate::ParseError;
    use crate::test_helpers::ArbitraryGenerator;

    proptest! {
        #[test]
        fn bitcoin_outpoint_ssz_roundtrip(txid_bytes in any::<[u8; 32]>(), vout in any::<u32>()) {
            let outpoint = BitcoinOutPoint(OutPoint {
                txid: Txid::from_byte_array(txid_bytes),
                vout,
            });

            let encoded = outpoint.as_ssz_bytes();
            let decoded = BitcoinOutPoint::from_ssz_bytes(&encoded).unwrap();

            prop_assert_eq!(decoded, outpoint);
        }

        #[test]
        fn bitcoin_txid_ssz_roundtrip(txid_bytes in any::<[u8; 32]>()) {
            let txid = BitcoinTxid::from(Txid::from_byte_array(txid_bytes));

            let encoded = txid.as_ssz_bytes();
            let decoded = BitcoinTxid::from_ssz_bytes(&encoded).unwrap();

            prop_assert_eq!(decoded, txid);
        }

        #[test]
        fn bitcoin_txout_ssz_roundtrip(
            value in any::<u64>(),
            script_pubkey in prop::collection::vec(any::<u8>(), 0..100),
        ) {
            let tx_out = BitcoinTxOut(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey),
            });

            let encoded = tx_out.as_ssz_bytes();
            let decoded = BitcoinTxOut::from_ssz_bytes(&encoded).unwrap();

            prop_assert_eq!(decoded, tx_out);
        }
    }

    #[test]
    fn bitcoin_outpoint_ssz_byte_layout() {
        // Guards the wire format: 32-byte txid followed by little-endian vout.
        let outpoint = BitcoinOutPoint(OutPoint {
            txid: Txid::from_byte_array([0xAB; 32]),
            vout: 0x01020304,
        });

        let mut expected = vec![0xAB; 32];
        expected.extend_from_slice(&0x01020304u32.to_le_bytes());

        assert_eq!(outpoint.as_ssz_bytes(), expected);
    }

    #[test]
    fn bitcoin_txid_ssz_byte_layout() {
        // Guards the wire format: the raw 32-byte txid with no length prefix.
        let txid = BitcoinTxid::from(Txid::from_byte_array([0xCD; 32]));
        assert_eq!(txid.as_ssz_bytes(), vec![0xCD; 32]);
    }

    #[test]
    fn test_bitcoin_tx_arbitrary_generation() {
        let mut generator = ArbitraryGenerator::new();
        let raw_tx: RawBitcoinTx = generator.generate();
        let _: Transaction = raw_tx.try_into().expect("should generate valid tx");

        let raw_tx = RawBitcoinTx::from_raw_bytes(generator.generate());
        let res: Result<Transaction, _> = raw_tx.try_into();
        assert!(res.is_err());
    }

    #[test]
    fn test_xonly_pk_to_descriptor() {
        let xonly_pk = BitcoinXOnlyPublicKey::new(Buf32::from([2u8; 32])).unwrap();
        let descriptor = xonly_pk.to_descriptor().unwrap();
        assert_eq!(descriptor.type_tag(), DescriptorType::P2tr);

        let payload = descriptor.payload();
        assert_eq!(payload.len(), 32);
        assert_eq!(payload, xonly_pk.0.as_bytes());
    }

    /// A script one byte larger than the SSZ-encodable maximum.
    fn oversized_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0u8; MAX_SCRIPT_SIZE as usize + 1])
    }

    #[test]
    fn bitcoin_txout_try_from_enforces_script_bound() {
        let max = MAX_SCRIPT_SIZE as usize;

        // A script exactly at the bound is accepted.
        let ok = TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; max]),
        };
        assert!(BitcoinTxOut::try_from(ok).is_ok());

        // One byte over the bound is rejected rather than producing a value that
        // would panic when SSZ-encoded.
        let too_big = TxOut {
            value: Amount::from_sat(1),
            script_pubkey: oversized_script(),
        };
        assert!(matches!(
            BitcoinTxOut::try_from(too_big),
            Err(ParseError::ScriptTooLarge { .. })
        ));
    }

    #[test]
    fn bitcoin_txout_serde_json_roundtrip() {
        // The derived `Serialize` and manual `Deserialize` must agree on the wire
        // format for an in-bound value.
        let tx_out = BitcoinTxOut::try_from(TxOut {
            value: Amount::from_sat(4321),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x21, 0xff]),
        })
        .unwrap();

        let json = serde_json::to_string(&tx_out).unwrap();
        let decoded: BitcoinTxOut = serde_json::from_str(&json).unwrap();
        assert_eq!(tx_out, decoded);
    }

    #[test]
    fn bitcoin_txout_deserialize_rejects_oversized_script() {
        // The validating serde `Deserialize` rejects an over-long script instead
        // of decoding a value that later panics on SSZ encoding.
        let tx_out = TxOut {
            value: Amount::from_sat(1),
            script_pubkey: oversized_script(),
        };
        let json = serde_json::to_string(&tx_out).unwrap();
        assert!(serde_json::from_str::<BitcoinTxOut>(&json).is_err());
    }

    #[test]
    fn bitcoin_scriptbuf_try_from_enforces_script_bound() {
        let max = MAX_SCRIPT_SIZE as usize;

        let ok = ScriptBuf::from_bytes(vec![0u8; max]);
        assert!(BitcoinScriptBuf::try_from(ok).is_ok());

        assert!(matches!(
            BitcoinScriptBuf::try_from(oversized_script()),
            Err(ParseError::ScriptTooLarge { .. })
        ));
    }

    // Property-based tests for BitcoinAmount SSZ serialization. The strategy is
    // bounded to valid amounts since construction now enforces `MAX_MONEY`.
    ssz_proptest!(
        BitcoinAmount,
        (0..=Amount::MAX_MONEY.to_sat()).prop_map(|sats| BitcoinAmount::try_from(sats).unwrap())
    );

    #[test]
    fn test_bitcoin_amount_zero_ssz() {
        let zero = BitcoinAmount::default();
        let encoded = zero.as_ssz_bytes();
        let decoded = BitcoinAmount::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(zero, decoded);
        // `to_sat` now comes from `Amount` through `Deref`.
        assert_eq!(decoded.to_sat(), 0);
    }

    #[test]
    fn bitcoin_amount_try_from_enforces_money_bound() {
        let max = Amount::MAX_MONEY.to_sat();

        // Exactly at the bound is accepted.
        assert!(BitcoinAmount::try_from(max).is_ok());

        // One sat over the money supply is rejected rather than producing a
        // value that violates the invariant.
        assert!(matches!(
            BitcoinAmount::try_from(max + 1),
            Err(ParseError::AmountTooLarge { .. })
        ));
    }

    #[test]
    fn bitcoin_amount_deserialize_rejects_over_max_money() {
        let over = Amount::MAX_MONEY.to_sat() + 1;

        // Serde and SSZ both reject an over-max value instead of decoding one
        // that violates the `MAX_MONEY` invariant.
        let json = serde_json::to_string(&over).unwrap();
        assert!(serde_json::from_str::<BitcoinAmount>(&json).is_err());

        assert!(BitcoinAmount::from_ssz_bytes(&over.as_ssz_bytes()).is_err());
    }

    // `BitcoinAmount` must implement `DecodeView` to be a field in a generated
    // SSZ container view.
    #[test]
    fn bitcoin_amount_impls_ssz_view_decode() {
        let amount = BitcoinAmount::try_from(100_000_000).unwrap();
        let bytes = amount.as_ssz_bytes();

        assert_eq!(
            <BitcoinAmount as ssz::view::DecodeView>::from_ssz_bytes(&bytes).unwrap(),
            amount,
        );
    }
}
