//! Discrete logarithm signature protocol

use super::wscalar::Wscalar;
use super::ProverMessage;
use alloc::boxed::Box;
use alloc::vec::Vec;
use ergo_chain_types::EcPoint;
use ergotree_ir::serialization::SigmaSerializable;

/// a = g^r, b = h^r
#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct FirstDhTupleProverMessage {
    #[cfg_attr(feature = "json", serde(rename = "a"))]
    a: Box<EcPoint>,
    #[cfg_attr(feature = "json", serde(rename = "b"))]
    b: Box<EcPoint>,
}

impl FirstDhTupleProverMessage {
    /// First message from the prover (message `a` and `b` of `SigmaProtocol`) for DhTuple case
    pub fn new(a: EcPoint, b: EcPoint) -> Self {
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

impl ProverMessage for FirstDhTupleProverMessage {
    #[allow(clippy::unwrap_used)] // since only EcPoint is serialized here it's safe to unwrap
    fn bytes(&self) -> Vec<u8> {
        let mut res = self.a.sigma_serialize_bytes().unwrap();
        res.append(self.b.sigma_serialize_bytes().unwrap().as_mut());
        res
    }
}

/// Second message from the prover (message `z` of `SigmaProtocol`) for DhTuple case
//z = r + ew mod q
#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct SecondDhTupleProverMessage {
    /// message `z`
    pub z: Wscalar,
}

/// Interactive prover
pub mod interactive_prover {
    use core::ops::Mul;

    use super::*;
    use crate::sigma_protocol::private_input::DhTupleProverInput;
    use crate::sigma_protocol::Challenge;
    use ergotree_ir::sigma_protocol::sigma_boolean::ProveDhTuple;
    use secp256k1::{Error, Scalar, SecretKey};

    /// Step 5 from <https://ergoplatform.org/docs/ErgoScript.pdf>
    /// For every leaf marked “simulated”, use the simulator of the sigma protocol for that leaf
    /// to compute the commitment "a" and the response "z", given the challenge "e" that
    /// is already stored in the leaf
    #[cfg(feature = "std")]
    pub(crate) fn simulate(
        public_input: &ProveDhTuple,
        challenge: &Challenge,
    ) -> Result<(FirstDhTupleProverMessage, SecondDhTupleProverMessage), Error> {
        use ergo_chain_types::ec_point::exponentiate;
        use ergotree_ir::sigma_protocol::dlog_group;
        //SAMPLE a random z <- Zq
        let z = dlog_group::random_scalar_in_group_range(
            crate::sigma_protocol::crypto_utils::secure_rng(),
        );

        // COMPUTE a = g^z*u^(-e) and b = h^z*v^{-e}  (where -e here means -e mod q)
        let e = SecretKey::try_from(challenge.clone())?;
        let minus_e = e.negate();
        let h_to_z = exponentiate(&public_input.h, &z);
        let g_to_z = exponentiate(&public_input.g, &z);
        let u_to_minus_e = exponentiate(&public_input.u, &minus_e);
        let v_to_minus_e = exponentiate(&public_input.v, &minus_e);
        let a = g_to_z.mul(&u_to_minus_e);
        let b = h_to_z.mul(&v_to_minus_e);
        Ok((
            FirstDhTupleProverMessage::new(a, b),
            SecondDhTupleProverMessage { z: z.into() },
        ))
    }

    /// Step 6 from <https://ergoplatform.org/docs/ErgoScript.pdf>
    /// For every leaf marked “real”, use the first prover step of the sigma protocol for
    /// that leaf to compute the necessary randomness "r" and the commitment "a"
    ///
    /// In this case (DH tuple) "a" is also a
    #[cfg(feature = "std")]
    pub fn first_message(public_input: &ProveDhTuple) -> (Wscalar, FirstDhTupleProverMessage) {
        use ergo_chain_types::ec_point::exponentiate;
        use ergotree_ir::sigma_protocol::dlog_group;
        let r = dlog_group::random_scalar_in_group_range(
            crate::sigma_protocol::crypto_utils::secure_rng(),
        );
        let a = exponentiate(&public_input.g, &r);
        let b = exponentiate(&public_input.h, &r);
        (r.into(), FirstDhTupleProverMessage::new(a, b))
    }

    /// Step 9 part 2 from <https://ergoplatform.org/docs/ErgoScript.pdf>
    /// compute its response "z" according to the second prover step(step 5 in whitepaper)
    /// of the sigma protocol given the randomness "r"(rnd) used for the commitment "a",
    /// the challenge "e", and witness w.
    pub(crate) fn second_message(
        private_input: &DhTupleProverInput,
        rnd: &Wscalar,
        challenge: &Challenge,
    ) -> Result<SecondDhTupleProverMessage, Error> {
        let e = SecretKey::try_from(challenge.clone())?;
        // modulo multiplication, no need to explicit mod op
        let ew = private_input
            .w
            .as_scalar_ref()
            .mul_tweak(&Scalar::from(e))?;
        // modulo addition, no need to explicit mod op
        let z = rnd.as_scalar_ref().add_tweak(&Scalar::from(ew))?;
        Ok(SecondDhTupleProverMessage { z: z.into() })
    }

    /// The function computes initial prover's commitment to randomness
    /// ("a" message of the sigma-protocol, which in this case has two parts "a" and "b")
    /// based on the verifier's challenge ("e")
    /// and prover's response ("z")
    ///
    /// g^z = a*u^e, h^z = b*v^e  => a = g^z/u^e, b = h^z/v^e
    #[allow(clippy::many_single_char_names)]
    pub fn compute_commitment(
        proposition: &ProveDhTuple,
        challenge: &Challenge,
        second_message: &SecondDhTupleProverMessage,
    ) -> Result<(EcPoint, EcPoint), Error> {
        let g = proposition.g.clone();
        let h = proposition.h.clone();
        let u = proposition.u.clone();
        let v = proposition.v.clone();

        let z = second_message.z.clone();

        let e = SecretKey::try_from(challenge.clone())?;

        use ergo_chain_types::ec_point::{exponentiate, inverse};

        let g_to_z = exponentiate(&g, z.as_scalar_ref());
        let h_to_z = exponentiate(&h, z.as_scalar_ref());

        let u_to_e = exponentiate(&u, &e);
        let v_to_e = exponentiate(&v, &e);

        let a = g_to_z.mul(&inverse(&u_to_e));
        let b = h_to_z.mul(&inverse(&v_to_e));
        Ok((a, b))
    }
}
