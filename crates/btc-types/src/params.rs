use std::io;

use bitcoin::params::{MAINNET, Params};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use ssz::DecodeError;
use strata_identifiers::{SszDelegate, impl_ssz_via_delegate};

/// Wrapper around Bitcoin consensus [`Params`] with serialization support.
#[derive(Debug, Clone)]
pub struct BtcParams(Params);

/// Maps a Bitcoin [`Network`](bitcoin::Network) to its SSZ selector index,
/// preserving the historical encoding (Bitcoin=0, Testnet=1, Signet=2,
/// Regtest=3).
fn conv_network_to_selector(network: bitcoin::Network) -> Option<u8> {
    Some(match network {
        bitcoin::Network::Bitcoin => 0,
        bitcoin::Network::Testnet => 1,
        bitcoin::Network::Signet => 2,
        bitcoin::Network::Regtest => 3,
        _ => return None,
    })
}

/// Inverse of [`conv_network_to_selector`].
fn conv_selector_to_network(selector: u8) -> Option<bitcoin::Network> {
    Some(match selector {
        0 => bitcoin::Network::Bitcoin,
        1 => bitcoin::Network::Testnet,
        2 => bitcoin::Network::Signet,
        3 => bitcoin::Network::Regtest,
        _ => return None,
    })
}

// SSZ encoding delegates to the upstream `u8` impl: the network is encoded as a
// single selector byte, so the layout is correct by construction rather than
// hand-rolled.
//
// NOTE: the ticket suggested modelling this as an SSZ `Union`. We deliberately
// keep the one-byte selector instead — `ssz-gen`'s `Union` emits standard union
// behaviour (a selector byte *plus* the serialized variant value), which would
// widen the encoding to two bytes and change the wire format.
impl SszDelegate for BtcParams {
    type Delegate = u8;

    fn into_delegate(self) -> Self::Delegate {
        conv_network_to_selector(self.0.network).expect("unsupported bitcoin network")
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        let network = conv_selector_to_network(delegate).ok_or_else(|| {
            DecodeError::BytesInvalid(format!("invalid bitcoin network index {delegate}"))
        })?;
        Ok(Self::from(Params::from(network)))
    }
}

impl_ssz_via_delegate!(BtcParams);

impl PartialEq for BtcParams {
    fn eq(&self, other: &Self) -> bool {
        // Just compare the network since all other params derive from it
        self.0.network == other.0.network
    }
}

impl Eq for BtcParams {}

impl Default for BtcParams {
    fn default() -> Self {
        BtcParams(MAINNET.clone())
    }
}

impl BorshSerialize for BtcParams {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        // Serialize the network type as an index since Network doesn't implement BorshSerialize
        let network_index = match self.0.network {
            bitcoin::Network::Bitcoin => 0u8,
            bitcoin::Network::Testnet => 1u8,
            bitcoin::Network::Signet => 2u8,
            bitcoin::Network::Regtest => 3u8,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported network type",
                ));
            }
        };
        BorshSerialize::serialize(&network_index, writer)
    }
}

impl BorshDeserialize for BtcParams {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let network_index = u8::deserialize_reader(reader)?;
        let network = match network_index {
            0 => bitcoin::Network::Bitcoin,
            1 => bitcoin::Network::Testnet,
            2 => bitcoin::Network::Signet,
            3 => bitcoin::Network::Regtest,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid network index",
                ));
            }
        };
        Ok(BtcParams::from(Params::from(network)))
    }
}

impl Serialize for BtcParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Just serialize the network - the rest can be derived from it
        self.0.network.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BtcParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let network = bitcoin::Network::deserialize(deserializer)?;
        Ok(BtcParams::from(Params::from(network)))
    }
}

impl<'a> arbitrary::Arbitrary<'a> for BtcParams {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let networks = [
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ];
        let network = u.choose(&networks)?;
        Ok(BtcParams::from(Params::from(*network)))
    }
}

impl From<Params> for BtcParams {
    fn from(params: Params) -> Self {
        BtcParams(params)
    }
}

impl BtcParams {
    /// Consumes self and returns the inner [`Params`].
    pub fn into_inner(self) -> Params {
        self.0
    }

    /// Returns a reference to the inner [`Params`].
    pub fn inner(&self) -> &Params {
        &self.0
    }

    /// Returns the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        self.0.difficulty_adjustment_interval()
    }
}

impl AsRef<Params> for BtcParams {
    fn as_ref(&self) -> &Params {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use ssz::{Decode, Encode};

    use super::*;

    #[test]
    fn test_all_networks_serialization() {
        let networks = [
            Network::Bitcoin,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ];

        for network in networks {
            let params = BtcParams::from(Params::from(network));

            // Test Borsh
            let borsh_data = borsh::to_vec(&params).unwrap();
            let borsh_result = borsh::from_slice::<BtcParams>(&borsh_data).unwrap();
            assert_eq!(params, borsh_result);

            // Test Serde
            let json_data = serde_json::to_string(&params).unwrap();
            let serde_result: BtcParams = serde_json::from_str(&json_data).unwrap();
            assert_eq!(params, serde_result);
        }
    }

    #[test]
    fn test_network_ssz_byte_layout() {
        // Guards the wire format: a single selector byte per network, preserving the
        // historical index mapping (Bitcoin=0, Testnet=1, Signet=2, Regtest=3).
        let cases = [
            (Network::Bitcoin, 0u8),
            (Network::Testnet, 1u8),
            (Network::Signet, 2u8),
            (Network::Regtest, 3u8),
        ];

        for (network, expected) in cases {
            let params = BtcParams::from(Params::from(network));
            assert_eq!(params.as_ssz_bytes(), vec![expected]);
        }
    }

    #[test]
    fn test_all_networks_ssz_roundtrip() {
        let networks = [
            Network::Bitcoin,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ];

        for network in networks {
            let params = BtcParams::from(Params::from(network));
            let encoded = params.as_ssz_bytes();
            let decoded = BtcParams::from_ssz_bytes(&encoded).unwrap();

            assert_eq!(params, decoded);
        }
    }
}
