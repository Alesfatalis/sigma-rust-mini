use ergotree_interpreter::sigma_protocol::{
    dlog_protocol::interactive_prover::first_message_deterministic,
    private_input::PrivateInput,
    prover::{
        hint::{CommitmentHint, Hint, HintsBag, OwnCommitment, RealCommitment},
        Prover,
    },
    unproven_tree::NodePosition,
    FirstProverMessage,
};
use ergotree_ir::sigma_protocol::sigma_boolean::{SigmaBoolean, SigmaProofOfKnowledgeTree};

pub(super) fn generate_commitments_for<P: Prover + ?Sized>(
    prover: &P,
    sigma_tree: &SigmaBoolean,
    msg: &[u8],
    aux_rand: &[u8],
) -> Option<HintsBag> {
    let position = NodePosition::crypto_tree_prefix();
    match sigma_tree {
        SigmaBoolean::ProofOfKnowledge(SigmaProofOfKnowledgeTree::ProveDlog(pk)) => {
            let PrivateInput::DlogProverInput(sk) = prover
                .secrets()
                .iter()
                .find(|secret| secret.public_image() == *sigma_tree)?
                .clone()
            else {
                return None;
            };
            let (r, a) = match first_message_deterministic(&sk, msg, aux_rand) {
                Some((r, a)) => (r, a),
                None => return None,
            };
            let mut bag = HintsBag::empty();
            let own_commitment: Hint =
                Hint::CommitmentHint(CommitmentHint::OwnCommitment(OwnCommitment {
                    image: SigmaBoolean::ProofOfKnowledge(pk.clone().into()),
                    secret_randomness: r,
                    commitment: FirstProverMessage::FirstDlogProverMessage(a.clone()),
                    position: position.clone(),
                }));
            let real_commitment: Hint =
                Hint::CommitmentHint(CommitmentHint::RealCommitment(RealCommitment {
                    image: SigmaBoolean::ProofOfKnowledge(pk.clone().into()),
                    commitment: FirstProverMessage::FirstDlogProverMessage(a),
                    position,
                }));
            bag.add_hint(real_commitment);
            bag.add_hint(own_commitment);
            Some(bag)
        }
        SigmaBoolean::TrivialProp(_)
        | SigmaBoolean::ProofOfKnowledge(_)
        | SigmaBoolean::SigmaConjecture(_) => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unreachable, clippy::panic)]
#[cfg(feature = "arbitrary")]
mod test {
    use ergo_chain_types::EcPoint;
    use ergotree_interpreter::sigma_protocol::dlog_protocol::interactive_prover::compute_commitment;
    use ergotree_interpreter::sigma_protocol::sig_serializer::parse_sig_compute_challenges;
    use ergotree_interpreter::sigma_protocol::unchecked_tree::{UncheckedLeaf, UncheckedTree};
    use ergotree_interpreter::sigma_protocol::{private_input::DlogProverInput, wscalar::Wscalar};
    use ergotree_ir::chain::context_extension::ContextExtension;
    use ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergotree_ir::chain::ergo_box::NonMandatoryRegisters;
    use ergotree_ir::chain::ergo_box::{arbitrary::ArbBoxParameters, ErgoBox};
    use ergotree_ir::sigma_protocol::sigma_boolean::SigmaProofOfKnowledgeTree;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use sigma_test_util::force_any_val;

    use crate::chain::ergo_box::box_builder::ErgoBoxCandidateBuilder;
    use crate::chain::transaction::unsigned::UnsignedTransaction;
    use crate::chain::transaction::{Input, Transaction, UnsignedInput};
    use crate::wallet::secret_key::SecretKey;
    use crate::wallet::signing::TransactionContext;
    use crate::wallet::Wallet;
    fn gen_boxes() -> impl Strategy<Value = (SecretKey, Vec<ErgoBox>)> {
        any::<Wscalar>()
            .prop_map(|s| SecretKey::DlogSecretKey(DlogProverInput { w: s }))
            .prop_flat_map(|sk: SecretKey| {
                (
                    Just(sk.clone()),
                    vec(
                        any_with::<ErgoBox>(ArbBoxParameters {
                            ergo_tree: Just(sk.get_address_from_public_image().script().unwrap())
                                .boxed(),
                            registers: Just(NonMandatoryRegisters::empty()).boxed(),
                            tokens: Just(None).boxed(),
                            ..Default::default()
                        }),
                        1..10,
                    ),
                )
            })
    }

    fn parse_sig(sk: &SecretKey, input: &Input) -> (EcPoint, Vec<u8>) {
        let ergotree_ir::chain::address::Address::P2Pk(pk) = sk.get_address_from_public_image()
        else {
            unreachable!()
        };
        let UncheckedTree::UncheckedLeaf(UncheckedLeaf::UncheckedSchnorr(schnorr)) =
            parse_sig_compute_challenges(
                &SigmaProofOfKnowledgeTree::from(pk.clone()).into(),
                input.spending_proof.proof.clone().to_bytes(),
            )
            .unwrap()
        else {
            unreachable!();
        };
        let commitment =
            compute_commitment(&pk, &schnorr.challenge, &schnorr.second_message).unwrap();
        (commitment, schnorr.challenge.into())
    }

    proptest! {
        // Produce signatures for different messages and test for nonce re-use
        #[test]
        fn test_sign_deterministic((sk, boxes) in gen_boxes()) {
            let wallet = Wallet::from_secrets(vec![sk.clone()]);
            let output = ErgoBoxCandidateBuilder::new(BoxValue::SAFE_USER_MIN, sk.get_address_from_public_image().script().unwrap(), 0).build().unwrap();
            let inputs: Vec<_> = boxes.iter().map(|b| UnsignedInput::new(b.box_id(), ContextExtension::empty())).collect();
            let txes: Vec<Transaction> = (1..10).map(|i| {
                let mut output = output.clone();
                output.value = output.value.checked_mul_u32(i).unwrap();
                let tx = UnsignedTransaction::new_from_vec(inputs.clone(), vec![], vec![output]).unwrap();
                wallet.sign_transaction_deterministic(TransactionContext::new(tx, boxes.clone(), vec![]).unwrap(), &force_any_val(), &[]).unwrap()
            }).collect();
            let signatures: Vec<_> = txes.iter().flat_map(|tx| tx.inputs.iter()).map(|input| parse_sig(&sk, input)).collect();

            for (i, (r, c)) in signatures.iter().enumerate() {
                if let Some((_, _)) = signatures.iter().enumerate().find(|(j, (r1, c1))| i != *j && r1 == r && c != c1) {
                    panic!();
                }
            }

        }
    }
}
