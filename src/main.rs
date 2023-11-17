use ark_std::{start_timer, end_timer};
use crate::halo2_base::{
    gates::circuit::builder::BaseCircuitBuilder,
    utils::BigPrimeField,
    utils::fs::gen_srs,
};
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::bn256::Fq12;
use halo2_ecc::bigint::ProperCrtUint;
use halo2_ecc::{
    
    bn254::pairing::PairingChip,
    bn254::FpChip,
    ecc::EcPoint,
    ecc::EccChip,
    fields::{fp12::Fp12Chip, fp2::Fp2Chip, FieldChip}
};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fr, G1Affine, G2Affine},
    plonk::*,
};
use snark_verifier_sdk::halo2::gen_snark_shplonk;
pub use halo2_base;
pub use halo2_base::halo2_proofs;
pub struct Bn254G1AffinePoint(EcPoint<Fr, FqPoint>);
type FqPoint = ProperCrtUint<Fr>;
use rand_core::{RngCore, OsRng};
use ruint::uint;

#[derive(Clone)]
struct EigenLayerCircuit {
    // constant:
    g1_one: G1Affine,
    all_operators_circuit_g1_apk: G1Affine,
    task_response_digest_bn254_g2: G2Affine,
    aggregate_signature: G2Affine,
    non_signer_pubkeys: Vec<G1Affine>,
}

impl EigenLayerCircuit {
    fn rand(num_non_signers: usize) -> Self {
        let mut rng = rand::thread_rng();
        // let non_signer_pubkeys: Vec<G1Affine> = (0..num_non_signers)
        // .map(|_| G1Affine::random(&mut rng))
        // .collect();

        // take random point as the hash output
        let task_response_digest_bn254_g2 = G2Affine::random(&mut rng);

        let d0 = Fr::from_u64_digits(&[OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64()]);
        let d1 = Fr::from_u64_digits(&[OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64()]);
        // Convert to Montgomery form
        let sk_all_operators_circuit_g1_apk = d0 * R2 + d1 * R3;
        let signature: G2Affine = G2Affine::from(task_response_digest_bn254_g2 * sk_all_operators_circuit_g1_apk);

        let mut all_operators_circuit_g1_apk = G1Affine::from(G1Affine::generator() * sk_all_operators_circuit_g1_apk);

        let mut signatures: Vec<G2Affine> = Vec::new();
        signatures.push(signature);
        let mut pubkeys: Vec<G1Affine> = Vec::new();

        /// `R^2 = 2^512 mod r`
        /// `0x216d0b17f4e44a58c49833d53bb808553fe3ab1e35c59e31bb8e645ae216da7`
        const R2: Fr = Fr::from_raw([
            1997599621687373223,
            6052339484930628067,
            10108755138030829701,
            150537098327114917,
        ]);

        /// `R^3 = 2^768 mod r`
        /// `0xcf8594b7fcc657c893cc664a19fcfed2a489cbe1cfbb6b85e94d8e1b4bf0040`
        const R3: Fr = Fr::from_raw([
            6815310600030060608,
            3046857488260118200,
            9888997017309401069,
            934595103480898940,
        ]);


        for _ in 0..num_non_signers {
            let d0 = Fr::from_u64_digits(&[OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64()]);
            let d1 = Fr::from_u64_digits(&[OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64(), OsRng.next_u64()]);
            // Convert to Montgomery form
            let sk = d0 * R2 + d1 * R3;
            // let signature: G2Affine = G2Affine::from(task_response_digest_bn254_g2 * sk);
            let pubkey = G1Affine::from(G1Affine::generator() * sk);
    
            // signatures.push(signature);
            pubkeys.push(pubkey);
        }

        for pubkey in pubkeys.iter() {
            all_operators_circuit_g1_apk = (all_operators_circuit_g1_apk + pubkey).into();
        }

        let large_number = uint!(0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_U256);
        println!("Parts: {:?}", large_number.into_limbs().map(|e| format!("0x{:x}", e)));
        Fr::from_u64_digits(&large_number.into_limbs());

        Self {
            g1_one: G1Affine::generator(),
            all_operators_circuit_g1_apk: all_operators_circuit_g1_apk,
            task_response_digest_bn254_g2: task_response_digest_bn254_g2,
            aggregate_signature: signature.clone(),
            non_signer_pubkeys: pubkeys,
        }

    }
}


fn main() {

    let mut circuit = BaseCircuitBuilder::<Fr>::new(false)
        .use_k(18)
        .use_lookup_bits(17)
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

    let el_circuit = EigenLayerCircuit::rand(1000);
    let signers_g1_apk;
    if !el_circuit.non_signer_pubkeys.is_empty() {
        let g1_points: Vec<_> = el_circuit
            .non_signer_pubkeys
            .into_iter()
            .map(|point| g1_chip.assign_point::<G1Affine>(circuit.main(0), point))
            .collect();
        let all_operators_circuit_g1_apk = g1_chip
            .assign_point::<G1Affine>(circuit.main(0), el_circuit.all_operators_circuit_g1_apk);
        let nonsigners_g1_apk = g1_chip.sum::<G1Affine>(circuit.main(0), g1_points);
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
    let _verification_result = fq12_chip.is_equal(circuit.main(0), result, fq12_one);
    // verification_result.cell.unwrap().offset
    dbg!(_verification_result.value());

    let params = circuit.calculate_params(Some(20));
    println!("params: {:?}", params);
    let circuit = circuit.use_params(params);

    MockProver::run(18, &circuit, vec![])
        .unwrap()
        .assert_satisfied();

    let params = gen_srs(18);

    let vk_time = start_timer!(|| "VK generation time");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);

    let pk_time = start_timer!(|| "PK generation time");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let proof_time = start_timer!(|| "Proving time");
    let _snark = gen_snark_shplonk(&params, &pk, circuit, Some("the.snark"));
    end_timer!(proof_time);
}
