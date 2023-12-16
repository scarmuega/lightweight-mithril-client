use anyhow::Context;
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use std::any::type_name;
use std::ops::Deref;

use crate::common::crypto_helper::{key_decode_hex, key_encode_hex};
use crate::common::StdResult;

/// A ProtocolKey is a wrapped that add Serialization capabilities.
///
/// When using serde to (de)serialize it will done using json hex (see [key_decode_hex] and
/// [key_encode_hex]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolKey<T>
where
    T: Serialize + DeserializeOwned,
{
    pub(crate) key: T,
}

/// The codec used to serialize/deserialize a [ProtocolKey].
///
/// Default to json hex.
pub trait ProtocolKeyCodec<T: Serialize + DeserializeOwned>: Sized {
    /// Do the decoding of the given key
    fn decode_key(encoded: &str) -> StdResult<ProtocolKey<T>> {
        ProtocolKey::from_json_hex(encoded)
    }

    /// Do the encoding of the given key
    fn encode_key(key: &T) -> StdResult<String> {
        ProtocolKey::key_to_json_hex(key)
    }
}

impl<T> ProtocolKey<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Create a ProtocolKey from the given key
    pub fn new(key: T) -> Self {
        Self { key }
    }

    /// Create an instance from a JSON hex representation
    pub fn from_json_hex(hex_string: &str) -> StdResult<Self> {
        let key = key_decode_hex::<T>(hex_string).with_context(|| {
            format!(
                "Could not deserialize a ProtocolKey from JSON hex string. Inner key type: {}",
                type_name::<T>()
            )
        })?;

        Ok(Self { key })
    }

    /// Create a JSON hash representation of the key
    pub fn to_json_hex(&self) -> StdResult<String> {
        Self::key_to_json_hex(&self.key)
    }

    /// Create a JSON hash representation of the given key
    pub fn key_to_json_hex(key: &T) -> StdResult<String> {
        key_encode_hex(key).with_context(|| {
            format!(
                "Could not serialize a ProtocolKey to JSON hex key string. Inner key type: {}",
                type_name::<T>()
            )
        })
    }
}

impl<T> Deref for ProtocolKey<T>
where
    T: Serialize + DeserializeOwned,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<T> Copy for ProtocolKey<T> where T: Copy + Serialize + DeserializeOwned {}

impl<T> Serialize for ProtocolKey<T>
where
    T: ProtocolKeyCodec<T> + Serialize + DeserializeOwned,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;
        let encoded = &T::encode_key(&self.key).map_err(Error::custom)?;

        encoded.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for ProtocolKey<T>
where
    T: ProtocolKeyCodec<T> + Serialize + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let string = String::deserialize(deserializer)?;

        T::decode_key(&string).map_err(Error::custom)
    }
}

impl<T> TryFrom<String> for ProtocolKey<T>
where
    T: ProtocolKeyCodec<T> + Serialize + DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        T::decode_key(&value)
    }
}

impl<T> TryFrom<&str> for ProtocolKey<T>
where
    T: ProtocolKeyCodec<T> + Serialize + DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        T::decode_key(value)
    }
}

impl<T> TryFrom<ProtocolKey<T>> for String
where
    T: ProtocolKeyCodec<T> + Serialize + DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: ProtocolKey<T>) -> Result<Self, Self::Error> {
        T::encode_key(&value.key)
    }
}

impl<T> TryFrom<&ProtocolKey<T>> for String
where
    T: ProtocolKeyCodec<T> + Serialize + DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: &ProtocolKey<T>) -> Result<Self, Self::Error> {
        T::encode_key(&value.key)
    }
}

/// Macro to batch define a [ProtocolKeyCodec] implementation and conversions From<ProtocolKey> / To
/// the given type and vis versa.
macro_rules! impl_codec_and_type_conversions_for_protocol_key {
    (json_hex_codec => $($key_type:ty),+) => {
        $(
            impl crate::common::crypto_helper::ProtocolKeyCodec<$key_type> for $key_type {}

            impl From<ProtocolKey<$key_type >> for $key_type {
                fn from(value: ProtocolKey<$key_type>) -> Self {
                    value.key
                }
            }

            impl From<$key_type> for ProtocolKey<$key_type> {
                fn from(value: $key_type) -> Self {
                    Self::new(value)
                }
            }
        )*
    };
    (no_default_codec => $($key_type:ty),+) => {
        $(
            impl From<ProtocolKey<$key_type >> for $key_type {
                fn from(value: ProtocolKey<$key_type>) -> Self {
                    value.key
                }
            }

            impl From<$key_type> for ProtocolKey<$key_type> {
                fn from(value: $key_type) -> Self {
                    Self::new(value)
                }
            }
        )*
    };
}
