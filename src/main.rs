use std::{cell::RefCell, borrow::BorrowMut};
use std::io::BufReader;
use std::rc::Rc;

use crate::halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
    AssignedValue,
    utils::BigPrimeField, 
};

pub mod ecc;
use ecc::Halo2Lib;
use halo2_base::utils::halo2;
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
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



fn main() {
    

    let mut circuit = BaseCircuitBuilder::<Fr>::new(false);
    let mut builder = circuit.borrow_mut();
    let ctx = builder.main(0);
    let g1_chip = EccChip::new(&fq_chip);
    let halo2Lib = Halo2Lib::new(circuit);
    let fq_chip = halo2Lib.bn254_fq_chip();
    
    let taskResponseDigestG2CoordsXC0 : BigPrimeField = 0;
    let taskResponseDigestG2CoordsXC1 : BigPrimeField = 0;
    let taskResponseDigestG2CoordsYC0 : BigPrimeField = 0;
    let taskResponseDigestG2CoordsYC1 : BigPrimeField = 0;
    let taskResponseDigestG2CoordsYC12 : u64 = 0;


    let aggSigG2CoordsXC0 : BigPrimeField = 0;
    let aggSigG2CoordsXC1 : BigPrimeField = 0;
    let aggSigG2CoordsYC0 : BigPrimeField = 0;
    let aggSigG2CoordsYC1 : BigPrimeField = 0;

    let taskCreatedBlock : BigPrimeField = 9961355;
    let blsPubkeyRegistryAddr: BigPrimeField = 0x7c46B99d6182dACCbeb3D82Eaff2Dc3266da7B02;
    let quorumG1ApkXSlot: BigPrimeField = 3;
    let quorumG1ApkYSlot: BigPrimeField = 4;

    let blsPubkeyCompendiumAddr: BigPrimeField = 0x40971B1c11c71D60e0e18E0B400a4ADD2485961F;
    let operatorToG1PubkeyXSlot: BigPrimeField = 0;
    let operatorToG1PubkeyYSlot: BigPrimeField = 1;
    let nonsignersAddrs: [BigPrimeField] = [];


    let taskResponseDigestG2Coords = halo2Lib.load_bn254_g2(taskResponseDigestG2CoordsXC0, 
        taskResponseDigestG2CoordsXC1, taskResponseDigestG2CoordsYC0, taskResponseDigestG2CoordsYC1);

    let aggSigG2Coords = halo2Lib.load_bn254_g2(aggSigG2CoordsXC0, 
        aggSigG2CoordsXC1, aggSigG2CoordsYC0, aggSigG2CoordsYC1);

    let quorumG1ApkSlot = halo2Lib.load_bn254_g1(quorumG1ApkXSlot, quorumG1ApkYSlot);
    let operatorToG1PubkeySlot = halo2Lib.load_bn254_g1(operatorToG1PubkeyXSlot, operatorToG1PubkeyYSlot);

    

}
