use std::io::BufReader;
use std::rc::Rc;
use std::{borrow::BorrowMut, cell::RefCell};

use crate::halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
    utils::BigPrimeField,
    utils::{fs::gen_srs, value_to_option, ScalarField},
    AssignedValue,
};

use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fq12, G1};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::CurveAffine;

use halo2_ecc::bigint::ProperCrtUint;
use halo2_ecc::{
    bn254::pairing::PairingChip,
    bn254::FpChip,
    ecc::EcPoint,
    ecc::EccChip,
    fields::{fp::FpConfig, fp12::Fp12Chip, fp2::Fp2Chip, FieldChip},
};
use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine, G2Affine},
    plonk::*,
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
};
use itertools::{concat, Itertools};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::halo2::gen_snark_shplonk;
// use snark_verifier::system::halo2::transcript_initial_state;
// use snark_verifier_sdk::{
//     halo2::{gen_snark_shplonk, PoseidonTranscript, POSEIDON_SPEC},
//     NativeLoader,
// };
use tsify::Tsify;

pub use halo2_base;
pub use halo2_base::halo2_proofs;
pub struct Bn254G1AffinePoint(EcPoint<Fr, FqPoint>);
type FqPoint = ProperCrtUint<Fr>;

struct EigenLayerConfig<F: BigPrimeField> {
    base_field_chip: FpConfig<F>,
    instance: Column<Instance>,
}

#[derive(Clone)]
struct EigenLayerCircuit<F: ScalarField> {
    // constant:
    g1_one: G1Affine,

    // Public inputs:
    //
    quorum_g1_apk: Value<G1Affine>,
    all_operators_circuit_g1_apk: G1Affine,
    // sum of pubkeys of ALL operators (including non-signers)
    aggregate_pubkey: Value<G2Affine>,
    task_response_digest_bn254_g2: G2Affine,
    aggregate_signature: G2Affine,
    non_signer: Vec<Value<F>>,
    non_signer_pubkeys: Vec<G1Affine>,
}

impl EigenLayerCircuit<Fr> {
    fn rand(num_non_signers: usize) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            g1_one: G1Affine::generator(),
            quorum_g1_apk: Value::known(G1Affine::random(&mut rng)),
            all_operators_circuit_g1_apk: G1Affine::random(&mut rng),
            aggregate_pubkey: Value::known(G2Affine::random(&mut rng)),
            task_response_digest_bn254_g2: G2Affine::random(&mut rng),
            aggregate_signature: G2Affine::random(&mut rng),
            non_signer: (0..num_non_signers)
                .map(|i| Value::known(Fr::from(2 * i as u64)))
                .collect(),
            non_signer_pubkeys: (0..num_non_signers)
                .map(|_| G1Affine::random(&mut rng))
                .collect(),
        }
    }
}

fn main() {
    let mut circuit = BaseCircuitBuilder::<Fr>::new(false)
        .use_k(25)
        .use_lookup_bits(22)
        ;

    let limb_bits = 88;
    let num_limbs = 3;

    let range = RangeChip::new(
        circuit.lookup_bits().unwrap(),
        circuit.lookup_manager().clone(),
    );
    let fq_chip = FpChip::<Fr>::new(&range, limb_bits, num_limbs);
    let fq2_chip = Fp2Chip::new(&fq_chip);

    let g1_chip = EccChip::new(&fq_chip);
    let g2_chip = EccChip::new(&fq2_chip);

    let el_circuit = EigenLayerCircuit::<Fr>::rand(10);
    let signers_g1_apk;
    if el_circuit.non_signer_pubkeys.len() > 0 {
        let g1_points: Vec<_> = el_circuit
            .non_signer_pubkeys
            .into_iter()
            .map(|point| g1_chip.assign_point::<G1Affine>(circuit.main(0), point))
            .collect();
        let all_operators_circuit_g1_apk = g1_chip
            .assign_point::<G1Affine>(circuit.main(0), el_circuit.all_operators_circuit_g1_apk);
        let nonsigners_g1_apk = g1_chip.sum::<G1Affine>(circuit.main(0), g1_points.into_iter());
        signers_g1_apk = g1_chip.sub_unequal(
            circuit.main(0),
            all_operators_circuit_g1_apk,
            nonsigners_g1_apk,
            true,
        );
    } else {
        signers_g1_apk = g1_chip
            .assign_point::<G1Affine>(circuit.main(0), el_circuit.all_operators_circuit_g1_apk);
    }

    let g1_generator = g1_chip.assign_point::<G1Affine>(circuit.main(0), el_circuit.g1_one);
    let neg_rhs_g1 = g1_chip.negate(circuit.main(0), g1_generator);
    let pairing_chip = PairingChip::new(&fq_chip);

    let aggregate_signature =
        g2_chip.assign_point::<G2Affine>(circuit.main(0), el_circuit.aggregate_signature);

    let task_response_digest_bn254_g2 =
        g2_chip.assign_point::<G2Affine>(circuit.main(0), el_circuit.task_response_digest_bn254_g2);
    let multi_paired = pairing_chip.multi_miller_loop(
        circuit.main(0),
        vec![
            (&signers_g1_apk, &task_response_digest_bn254_g2),
            (&neg_rhs_g1, &aggregate_signature),
        ],
    );
    let fq12_chip = Fp12Chip::new(&fq_chip);
    let result = fq12_chip.final_exp(circuit.main(0), multi_paired);
    let fq12_one = fq12_chip.load_constant(circuit.main(0), Fq12::one());
    let verification_result = fq12_chip.is_equal(circuit.main(0), result, fq12_one);
    // verification_result.cell.unwrap().offset

    let params = circuit.calculate_params(Some(20));
    let circuit = circuit.use_params(params);

    MockProver::run(25, &circuit, vec![])
        .unwrap()
        .assert_satisfied();

    let params = gen_srs(25);
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let snark = gen_snark_shplonk(&params, &pk, circuit, Some("el.snark"));
}
