//! Elliptic curve point.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::{Mul, Neg};
use derive_more::{From, Into};
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sigma_ser::vlq_encode::{ReadSigmaVlqExt, WriteSigmaVlqExt};
use sigma_ser::{
    ScorexParsingError, ScorexSerializable, ScorexSerializationError, ScorexSerializeResult,
};

/// Elliptic curve point
#[derive(PartialEq, Clone, From, Into)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "String", try_from = "String")
)]
pub struct EcPoint(PublicKey);

#[allow(clippy::unwrap_used)]
impl core::fmt::Debug for EcPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("EC:")?;
        f.write_str(&base16::encode_lower(
            &self.scorex_serialize_bytes().unwrap(),
        ))
    }
}

#[allow(clippy::unwrap_used)]
impl core::fmt::Display for EcPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&base16::encode_lower(
            &self.scorex_serialize_bytes().unwrap(),
        ))
    }
}

impl EcPoint {
    /// Number of bytes to represent any group element as byte array
    pub const GROUP_SIZE: usize = 33;

    /// Attempts to parse from Base16-encoded string
    pub fn from_base16_str(str: String) -> Option<Self> {
        base16::decode(&str)
            .ok()
            .and_then(|bytes| Self::scorex_parse_bytes(&bytes).ok())
    }

    /// Returns PublicKey of EcPoint
    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }
}

impl TryFrom<String> for EcPoint {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        EcPoint::from_base16_str(value)
            .ok_or_else(|| String::from("Ecpoint: error parsing from base16-encoded string"))
    }
}

impl From<EcPoint> for String {
    fn from(value: EcPoint) -> String {
        #[allow(clippy::unwrap_used)]
        {
            let bytes = value.scorex_serialize_bytes().unwrap();
            base16::encode_lower(&bytes)
        }
    }
}

impl Eq for EcPoint {}

impl Mul<&EcPoint> for EcPoint {
    type Output = EcPoint;

    fn mul(self, other: &EcPoint) -> EcPoint {
        match self.0.combine(&other.0) {
            Ok(pub_key) => EcPoint(pub_key),
            Err(_) => EcPoint(self.0),
        }
    }
}

impl Neg for EcPoint {
    type Output = EcPoint;

    fn neg(self) -> EcPoint {
        EcPoint(self.0.negate(&Secp256k1::new()))
    }
}

/// The generator g of the group is an element of the group such that, when written multiplicatively, every element
/// of the group is a power of g.
pub fn generator() -> EcPoint {
    let whole: Vec<u8> = [4]
        .iter()
        .chain(GENERATOR_X.iter())
        .chain(GENERATOR_Y.iter())
        .copied()
        .collect();
    #[allow(clippy::unwrap_used)]
    EcPoint(PublicKey::from_slice(whole.as_slice()).unwrap())
}

/// Calculates the inverse of the given group element
pub fn inverse(ec: &EcPoint) -> EcPoint {
    ec.clone().neg()
}

/// Raises the base GroupElement to the exponent. The result is another GroupElement.
pub fn exponentiate(base: &EcPoint, exponent: &SecretKey) -> EcPoint {
    match base
        .0
        .mul_tweak(&Secp256k1::new(), &Scalar::from(*exponent))
    {
        Err(_) => base.clone(),
        Ok(public_key) => EcPoint(public_key),
    }
}

impl ScorexSerializable for EcPoint {
    fn scorex_serialize<W: WriteSigmaVlqExt>(&self, w: &mut W) -> ScorexSerializeResult {
        w.write_all(&self.0.serialize())
            .map_err(ScorexSerializationError::from)
    }

    fn scorex_parse<R: ReadSigmaVlqExt>(r: &mut R) -> Result<Self, ScorexParsingError> {
        let mut buf = [0; EcPoint::GROUP_SIZE];
        r.read_exact(&mut buf[..])?;
        let pubkey = PublicKey::from_byte_array_compressed(&buf).map_err(|e| {
            ScorexParsingError::Misc(format!("failed to parse PK from bytes: {:?}", e))
        })?;
        Ok(EcPoint(pubkey))
    }
}

/// Arbitrary impl for EcPoint
#[cfg(feature = "arbitrary")]
mod arbitrary {
    use super::*;
    use proptest::prelude::*;

    impl Arbitrary for EcPoint {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(generator()),
                //Just(identity()), /*Just(random_element()),*/
            ]
            .boxed()
        }
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
#[cfg(feature = "arbitrary")]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sigma_ser::scorex_serialize_roundtrip;

    proptest! {

        #[test]
        fn ser_roundtrip(v in any::<EcPoint>()) {
            prop_assert_eq![scorex_serialize_roundtrip(&v), v];
        }

    }
}
