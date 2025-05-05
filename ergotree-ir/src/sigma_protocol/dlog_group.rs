//! This is the general interface for the discrete logarithm prime-order group.
//!
//! The discrete logarithm problem is as follows: given a generator g of a finite
//! group G and a random element h in G, find the (unique) integer x such that
//! `g^x = h`.
//!
//! In cryptography, we are interested in groups for which the discrete logarithm problem
//! (Dlog for short) is assumed to be hard. The most known groups of that kind are some Elliptic curve groups.
//!
//! Another issue pertaining elliptic curves is the need to find a suitable mapping that will convert an arbitrary
//! message (that is some binary string) to an element of the group and vice-versa.
//!
//! Only a subset of the messages can be effectively mapped to a group element in such a way that there is a one-to-one
//! injection that converts the string to a group element and vice-versa.
//!
//! On the other hand, any group element can be mapped to some string.

use crate::bigint256::BigInt256;
use crate::serialization::sigma_byte_writer::SigmaByteWrite;
use crate::serialization::SigmaSerializeResult;
use crate::serialization::{
    sigma_byte_reader::SigmaByteRead, SigmaParsingError, SigmaSerializable,
};
use bnum::cast::CastFrom;
use bnum::types::{I256, U256};
use bnum::BTryFrom;
use elliptic_curve::rand_core::RngCore;
use num_bigint::BigInt;
use num_traits::Num;
use secp256k1::{constants, SecretKey};
use sigma_ser::ScorexSerializable;

// /// Creates a random member of this Dlog group
// pub fn random_element() -> EcPoint {
//     let sk = DlogProverInput::random();
//     exponentiate(&generator(), &sk.w)
// }

/// Creates a random scalar, a big-endian integer in the range [0, n), where n is group order
/// Use cryptographically secure PRNG (like rand::thread_rng())
pub fn random_scalar_in_group_range(mut rng: impl RngCore) -> SecretKey {
    let mut bytes = [0u8; constants::SECRET_KEY_SIZE];
    loop {
        rng.fill_bytes(&mut bytes);
        if let Ok(scalar) = SecretKey::from_byte_array(&bytes) {
            return scalar;
        }
    }
}

/// Attempts to create BigInt256 from Scalar
/// Returns None if s > 2^255 - 1
/// Since Scalar is in [0, n) range, where n is the group order
/// (FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141)
/// it might not fit into 256-bit BigInt because BigInt uses 1 bit for sign.
pub fn scalar_to_bigint256(s: SecretKey) -> Option<BigInt256> {
    // from https://github.com/RustCrypto/elliptic-curves/blob/fe737c56add103e4e8ff270d0c05ffdb6107b8d6/k256/src/arithmetic/scalar.rs#L598-L602
    let bytes = s.secret_bytes();
    #[allow(clippy::unwrap_used)] // Scalar always fits in 256-bit unsigned integer
    let uint = U256::from_be_slice(&bytes).unwrap();
    <I256 as BTryFrom<U256>>::try_from(uint)
        .ok()
        .map(Into::into)
}

/// Attempts to create Scalar from BigInt256
/// Returns None if not in the range [0, modulus).
pub fn bigint256_to_scalar(bi: BigInt256) -> Option<SecretKey> {
    type I257 = bnum::BIntD8<33>;
    use num_traits::identities::Zero;
    // To convert BigInt bi to Scalar calculate (bi mod order). Widen signed calculations to 257 bits since secp256k1 order doesn't fit in 256 bits signed
    let order: I257 = I257::cast_from(order());
    let mut bi: I257 = I257::cast_from(bi.0) % order;
    if bi < I257::zero() {
        bi += order;
    }
    #[allow(clippy::unwrap_used)] // bi is positive, and bi < order() < U256::MAX
    let bytes = *<bnum::BUintD8<32> as BTryFrom<bnum::BIntD8<33>>>::try_from(bi)
        .unwrap()
        .to_be()
        .digits();
    match SecretKey::from_byte_array(&bytes) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

impl SigmaSerializable for ergo_chain_types::EcPoint {
    fn sigma_serialize<W: SigmaByteWrite>(&self, w: &mut W) -> SigmaSerializeResult {
        self.scorex_serialize(w)?;
        Ok(())
    }

    fn sigma_parse<R: SigmaByteRead>(r: &mut R) -> Result<Self, SigmaParsingError> {
        let e = Self::scorex_parse(r)?;
        Ok(e)
    }
}

const ORDER: &str = "+FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
/// Order of the secp256k1 elliptic curve
// Since secp256k1 order doesn't fit in a signed 256 bit integer, this returns an unsigned 256-bit integer instead
pub fn order() -> U256 {
    #[allow(clippy::unwrap_used)]
    U256::from_str_radix(ORDER, 16).unwrap()
}

/// Order of the secp256k1 elliptic curve as BigInt
pub fn order_bigint() -> BigInt {
    #[allow(clippy::unwrap_used)]
    BigInt::from_str_radix(ORDER, 16).unwrap()
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
#[cfg(feature = "arbitrary")]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn scalar() -> impl Strategy<Value = SecretKey> {
        any::<[u8; 32]>().prop_filter_map(
            format!("Scalars must be 0 <= n < {0}", order()),
            |bytes| {
                if bytes[0] & 0x80 != 0 {
                    return None;
                }
                Some(SecretKey::from_byte_array(&bytes).unwrap())
            },
        )
    }

    proptest! {

        #[test]
        fn scalar_biguint_roundtrip(scalar in scalar()) {
            let bu = scalar_to_bigint256(scalar).unwrap();
            let to_scalar = bigint256_to_scalar(bu).unwrap();
            prop_assert_eq!(scalar, to_scalar);
        }

        //TODO: re enable when solution for rightshift is found
       /* #[test]
        fn scalar_bigint256_roundtrip(scalar in scalar()) {
            // Shift right to make sure that the MSB is 0, so that the Scalar can be
            // converted to a BigInt256
            let shifted_scalar = scalar >> 1;
            let as_bigint256: BigInt256 = scalar_to_bigint256(shifted_scalar).unwrap();
            let to_scalar = bigint256_to_scalar(as_bigint256).unwrap();
            prop_assert_eq!(shifted_scalar, to_scalar);
        }*/
    }
}
