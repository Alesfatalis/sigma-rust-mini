//! Wrapper for Scalar
//! mainly for Arbitrary impl and JSON encoding

use core::convert::TryFrom;
use core::fmt::Formatter;

use super::challenge::Challenge;
use super::GroupSizedBytes;
use super::SOUNDNESS_BYTES;
use derive_more::From;
use derive_more::Into;
use ergo_chain_types::Base16DecodedBytes;
use ergo_chain_types::Base16EncodedBytes;
use secp256k1::SecretKey;

#[derive(PartialEq, Eq, From, Into, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "json",
    serde(
        try_from = "ergo_chain_types::Base16DecodedBytes",
        into = "ergo_chain_types::Base16EncodedBytes"
    )
)]
/// Wrapper for Scalar mainly for Arbitrary impl and JSON encoding
pub struct Wscalar(SecretKey);

impl Wscalar {
    /// Returns a reference to underlying Scalar
    pub fn as_scalar_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl TryFrom<GroupSizedBytes> for Wscalar {
    type Error = secp256k1::Error;

    fn try_from(b: GroupSizedBytes) -> Result<Self, Self::Error> {
        let sl: &[u8; 32] = b.0.as_ref();
        let s = SecretKey::from_byte_array(sl)?;
        Ok(Wscalar(s))
    }
}

impl TryFrom<Challenge> for SecretKey {
    type Error = secp256k1::Error;
    fn try_from(v: Challenge) -> Result<Self, Self::Error> {
        let v: [u8; SOUNDNESS_BYTES] = v.0.into();
        // prepend zeroes to 32 bytes (big-endian)
        let mut prefix = vec![0u8; 8];
        prefix.append(&mut v.to_vec());
        let bytes: &[u8; 32] = prefix
            .as_slice()
            .try_into()
            .map_err(|_| secp256k1::Error::InvalidSecretKey)?;
        SecretKey::from_byte_array(bytes)
    }
}

impl From<Wscalar> for Base16EncodedBytes {
    fn from(w: Wscalar) -> Self {
        let bytes = w.0.secret_bytes();
        let bytes_ref: &[u8] = bytes.as_ref();
        Base16EncodedBytes::new(bytes_ref)
    }
}

impl TryFrom<Base16DecodedBytes> for Wscalar {
    type Error = secp256k1::Error;

    fn try_from(value: Base16DecodedBytes) -> Result<Self, Self::Error> {
        let bytes = value.0;
        match GroupSizedBytes::try_from(bytes) {
            Ok(group) => Ok(Wscalar::try_from(group)?),
            Err(_) => Err(secp256k1::Error::InvalidSecretKey),
        }
    }
}

impl core::fmt::Debug for Wscalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Wscalar:")?;
        f.write_str(&base16::encode_lower(&self.0.secret_bytes()))
    }
}

#[cfg(feature = "arbitrary")]
#[allow(clippy::unwrap_used)]
mod arbitrary {
    use super::Wscalar;
    use proptest::{array::uniform32, prelude::*};
    use secp256k1::{Error, SecretKey};

    impl Arbitrary for Wscalar {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            uniform32(any::<u8>())
                .prop_filter("must be in group range", |bytes| {
                    let res: Result<SecretKey, Error> = SecretKey::from_byte_array(bytes);
                    res.is_ok()
                })
                .prop_map(|bytes| SecretKey::from_byte_array(&bytes).unwrap().into())
                .boxed()
        }
    }
}
