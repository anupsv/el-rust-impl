use std::{cell::RefCell, borrow::BorrowMut};
use std::io::BufReader;
use std::rc::Rc;

use crate::halo2_base::{
    utils::{value_to_option, fs::gen_srs, ScalarField}, 
    gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
    AssignedValue,
    utils::BigPrimeField,
};

use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;

use halo2_ecc::bigint::ProperCrtUint;
use halo2_ecc::{
    bn254::FpChip,
    fields::{fp::{FpConfig},
    fp2::Fp2Chip, fp12::Fp12Chip, FieldChip}, 
    ecc::{EccChip}, 
    bn254::pairing::PairingChip,
    ecc::EcPoint,
};
use halo2_proofs::{
    dev::MockProver,
    circuit::{Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine, Fq},
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
    instance: Column<Instance>
}

#[derive(Clone)]
struct EigenLayerCircuit<F: ScalarField> {
    // constant:
    g1_one: G1Affine,
    g2_one: G2Affine,

    // Public inputs:
    // 
    quorumG1Apk: Value<G1Affine>,
    allOperatorsCircuitG1Apk: Value<G1Affine>,
    // sum of pubkeys of ALL operators (including non-signers)
    aggregate_pubkey: Value<G2Affine>,
    taskResponseDigestBn254G2: Value<G2Affine>,
    aggregate_signature: G2Affine,
    non_signer: Vec<Value<F>>,

    non_signer_pubkeys: Vec<G2Affine>, 

    // Public output:
    // 
    // H - R(alpha)[1]_1 - Z(alpha) pi_H + alpha pi'_H is a G1 point
    verifier_point: G1Affine,
}

impl EigenLayerCircuit<Fr> {
    fn rand(num_non_signers: usize) -> Self {
        let mut rng = rand::thread_rng(); 
        Self { 
            g1_one: G1Affine::generator(), 
            g2_one: G2Affine::generator(), 
            quorumG1Apk: Value::known(G1Affine::random(&mut rng)),
            allOperatorsCircuitG1Apk: Value::known(G1Affine::random(&mut rng)),
            aggregate_pubkey: Value::known(G2Affine::random(&mut rng)), 
            taskResponseDigestBn254G2: Value::known(G2Affine::random(&mut rng)),
            aggregate_signature: G2Affine::random(&mut rng), 
            non_signer: (0..num_non_signers).map(|i| Value::known(Fr::from(2* i as u64))).collect(), 
            non_signer_pubkeys: (0..num_non_signers).map(|_| G2Affine::random(&mut rng)).collect(), 
            verifier_point: G1Affine::random(&mut rng), 
        }
    }
}


fn main() {
    

    let mut circuit = BaseCircuitBuilder::<Fr>::new(false).use_lookup_bits(22);

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
    // let signers_g1_apk;
    if el_circuit.non_signer_pubkeys.len() > 0 {

        let g2_points: Vec<_> = el_circuit.non_signer_pubkeys
            .into_iter()
            .map(|point| g2_chip.assign_point::<G2Affine>(circuit.main(0), point))
            .collect();

        let nonsigners_g2_apk = g2_chip.sum::<G2Affine>(circuit.main(0), g2_points.into_iter());
        // nonsigners_g2_apk = g2_chip.sub_unequal::<G2Affine>(circuit.main(0), el_circuit.allOperatorsCircuitG1Apk, nonsigners_g2_apk, true);

    } else {
        // signers_g1_apk = circuit.allOperatorsCircuitG1Apk;
    }

    let assigned = g1_chip.assign_point::<G1Affine>(circuit.main(0), el_circuit.g1_one);
    let neg_rhs_g1 = g1_chip.negate(circuit.main(0), assigned);
    let pairing_chip = PairingChip::new(&fq_chip);

    let test = g2_chip.assign_point::<G2Affine>(circuit.main(0), el_circuit.aggregate_signature);
    
    let multi_paired = pairing_chip.multi_miller_loop(circuit.main(0), vec![(el_circuit.signers_g1_apk, &circuit.taskResponseDigestBn254G2), (&neg_rhs_g1, &test)]);
    // let fq12_chip = Bn254Fq12Chip::new(&fq_chip);
    // let result = fq12_chip.final_exp(ctx, multi_paired);
    // let fq12_one = fq12_chip.load_constant(ctx, Bn254Fq12::one());
    // let verification_result = fq12_chip.is_equal(ctx, result, fq12_one);
    // verification_result.cell.unwrap().offset
    

}
