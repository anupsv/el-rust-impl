use std::{cell::RefCell, borrow::BorrowMut};
use std::io::BufReader;
use std::rc::Rc;

use crate::halo2_base::{
    utils::{value_to_option, fs::gen_srs, ScalarField}, 
    gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
    AssignedValue,
    utils::BigPrimeField, 
};

pub mod ecc;
use ecc::{Halo2Lib, JsCircuitValue256};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;

use halo2_ecc::{
    fields::{fp::{FpConfig}, 
    fp2::Fp2Chip, fp12::Fp12Chip, FieldChip}, 
    ecc::{EccChip}, 
    bn254::pairing::PairingChip
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
    aggregate_signature: Value<G1Affine>,
    non_signer: Vec<Value<F>>,

    non_signer_pubkeys: Vec<Value<G2Affine>>, 

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
            aggregate_signature: Value::known(G1Affine::random(&mut rng)), 
            non_signer: (0..num_non_signers).map(|i| Value::known(Fr::from(2* i as u64))).collect(), 
            non_signer_pubkeys: (0..num_non_signers).map(|_| Value::known(G2Affine::random(&mut rng))).collect(), 
            verifier_point: G1Affine::random(&mut rng), 
        }
    }
}


fn main() {
    

    let mut circuit = BaseCircuitBuilder::<Fr>::new(false);
    let mut builder = circuit.borrow_mut();
    let ctx = builder.main(0);
    let g1_chip = EccChip::new(&fq_chip);
    
    let circuit = EigenLayerCircuit::<Fr>::rand(100); 
    let signers_g1_apk;
    if circuit.non_signer_pubkeys.len() > 0 {
        let nonsigners_g1_apk = g1_chip.sum::<G1Affine>(builder.borrow_mut().main(0), circuit.non_signer_pubkeys);
        nonsigners_g1_apk = g1_chip.sub_equal::<G1Affine>(builder.borrow_mut().main(0), circuit.allOperatorsCircuitG1Apk, nonsigners_g1_apk);

    } else {
        signers_g1_apk = circuit.allOperatorsCircuitG1Apk;
    }


    let fq_chip = self.bn254_fq_chip();
    let g1_chip = EccChip::new(&fq_chip);
    let neg_rhs_g1 = g1_chip.negate(ctx, circuit.g1_one.0);
    let pairing_chip = PairingChip::new(&fq_chip);

    let multi_paired = pairing_chip.multi_miller_loop(ctx, vec![(&signers_g1_apk.0, &circuit.taskResponseDigestBn254G2.0), (&neg_rhs_g1, &circuit.aggregate_signature.0)]);
    let fq12_chip = Bn254Fq12Chip::new(&fq_chip);
    let result = fq12_chip.final_exp(ctx, multi_paired);
    let fq12_one = fq12_chip.load_constant(ctx, Bn254Fq12::one());
    let verification_result = fq12_chip.is_equal(ctx, result, fq12_one);
    verification_result.cell.unwrap().offset
    

}
