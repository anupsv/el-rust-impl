use halo2_base::{
    gates::{
        circuit::builder::BaseCircuitBuilder,
        flex_gate::{GateChip, GateInstructions},
        range::{RangeChip, RangeInstructions},
    },
    utils::BigPrimeField, 
    QuantumCell::Constant, halo2_proofs::halo2curves::pasta::Fp,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bn254::pairing::PairingChip,
    ecc::EcPoint,
    fields::{fp::FpChip, vector::FieldVector},
};
pub use halo2_ecc::{
    bn254::{Fp12Chip as Bn254Fq12Chip, Fp2Chip as Bn254Fq2Chip, FpChip as Bn254FqChip},
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
    secp256k1::{FpChip as Secp256k1FpChip, FqChip as Secp256k1FqChip},
};
use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

pub use crate::halo2_proofs::halo2curves::{
    bn256::{
        Fq as Bn254Fq, Fq12 as Bn254Fq12, Fq2 as Bn254Fq2, Fr as Bn254Fr,
        G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine,
    },
    secp256k1::{Fp as Secp256k1Fp, Fq as Secp256k1Fq, Secp256k1Affine},
};

use super::*;

pub struct Bn254G1AffinePoint(EcPoint<Fr, FqPoint>);

// hardcoding for 3 limbs
fn constrain_limbs_equality<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    [hi, lo]: [AssignedValue<F>; 2],
    limbs: &[AssignedValue<F>],
    limb_bits: usize,
) {
    assert!(limb_bits <= 128);
    assert!(limb_bits > 64);
    // limb_bits, 128 - limb_bits
    let (tmp0, limb0) = range.div_mod(ctx, lo, BigUint::one() << limb_bits, 128);
    // limb_bits - (128 - limb_bits) = 2 * limb_bits - 128 > 0
    let rem_bits = limb_bits - (128 - limb_bits);
    let (limb2, tmp1) = range.div_mod(ctx, hi, BigUint::one() << rem_bits, 128);
    let multiplier = biguint_to_fe(&(BigUint::one() << (128 - limb_bits)));
    let limb1 = range.gate.mul_add(ctx, tmp1, Constant(multiplier), tmp0);
    for (l0, l1) in limbs.iter().zip_eq([limb0, limb1, limb2]) {
        ctx.constrain_equal(l0, &l1);
    }
}

type FqPoint = ProperCrtUint<Fr>;
pub type JsCircuitValue = usize;
pub struct Bn254G2AffinePoint(EcPoint<Fr, Fq2Point>);
pub struct Halo2Lib {
    pub gate: GateChip<Fr>,
    pub range: RangeChip<Fr>,
    pub builder: Rc<RefCell<BaseCircuitBuilder<Fr>>>,
}

pub struct JsCircuitBn254G2Affine {
    pub x: JsCircuitBn254Fq2,
    pub y: JsCircuitBn254Fq2,
}

pub struct JsCircuitBn254G1Affine {
    pub x: JsCircuitValue256,
    pub y: JsCircuitValue256,
}

pub struct JsCircuitBn254Fq2 {
    pub c0: JsCircuitValue256,
    pub c1: JsCircuitValue256,
}

pub struct JsCircuitValue256 {
    pub hi: JsCircuitValue,
    pub lo: JsCircuitValue,
}

impl Halo2Lib {

    pub fn new(circuit: BaseCircuitBuilder<Fr>) -> Self {
        let gate: GateChip<_> = GateChip::new();
        let lookup_bits = circuit.lookup_bits.unwrap();
        let range = RangeChip::new(
            lookup_bits,
            circuit.lookup_manager().clone(),
        );
        Halo2Lib {
            gate,
            range,
            builder: Rc::clone(&circuit.borrow_mut()),
        }
    }

    fn get_assigned_value(&self, idx: usize) -> AssignedValue<Fr> {
        self.builder.borrow().core().phase_manager[0]
            .threads
            .last()
            .unwrap()
            .get(idx as isize)
    }

    fn get_assigned_values(&self, a: &[u32]) -> Vec<AssignedValue<Fr>> {
        a.iter()
            .map(|x| self.get_assigned_value(*x as usize))
            .collect()
    }

    pub fn bn254_fq_chip(&self) -> Bn254FqChip<Fr> {
        let limb_bits = 88;
        let num_limbs = 3;
        Bn254FqChip::<Fr>::new(&self.range, limb_bits, num_limbs)
    }

    // Doesn't range check hi,lo
    fn load_generic_fp_impl<Fp: BigPrimeField>(
        &self,
        fp_chip: &FpChip<Fr, Fp>,
        val: Fp,
    ) -> ProperCrtUint<Fr> {
        // easiest to just construct the raw bigint, load it as witness, and then constrain against provided circuit value
        // let [hi, lo] = [val.hi, val.lo].map(|x| self.get_assigned_value(x));
        // let [hi_val, lo_val] = [hi, lo].map(|x| fe_to_biguint(x.value()));
        assert!(val < modulus::<Fp>());
        let mut builder = self.builder.borrow_mut();
        let ctx = builder.main(0);
        let fp = fp_chip.load_private(ctx, val);
        // constrain fq actually equals hi << 128 + lo
        constrain_limbs_equality(ctx, &self.range, [hi, lo], fp.limbs(), fp_chip.limb_bits());
        fp
    }
    
    /// Doesn't range check limbs of g1_point.
    /// Does not allow you to load identity point.
    pub fn load_bn254_g1(&self, point: JsCircuitBn254G1Affine) -> Bn254G1AffinePoint {
        let fq_chip = self.bn254_fq_chip();
        let g1_chip = EccChip::new(&fq_chip);
        self.load_bn254_g1_impl(&g1_chip, point)
    }

    /// Doesn't range check limbs of g1_point
    fn load_bn254_g1_impl(
        &self,
        g1_chip: &EccChip<Fr, Bn254FqChip<Fr>>,
        point: JsCircuitBn254G1Affine,
    ) -> Bn254G1AffinePoint {
        let [x, y] = [point.x, point.y]
            .map(|c| self.load_generic_fp_impl::<Bn254Fq>(g1_chip.field_chip(), c));
        let pt = EcPoint::new(x, y);
        g1_chip.assert_is_on_curve::<Bn254G1Affine>(self.builder.borrow_mut().main(0), &pt);
        Bn254G1AffinePoint(pt)
    }
    
    /// Doesn't range check limbs of g2_point.
    /// Does not allow you to load identity point.
    pub fn load_bn254_g2(&self, point: JsCircuitBn254G2Affine) -> Bn254G2AffinePoint {
        let fq_chip = self.bn254_fq_chip();
        let fq2_chip = Bn254Fq2Chip::new(&fq_chip);
        let g2_chip = EccChip::new(&fq2_chip);
        self.load_bn254_g2_impl(&g2_chip, point)
    }

    pub fn bn254_g1_sum(&self, g1_points: &[G1Affine]) -> Bn254G1AffinePoint {
        let fq_chip = self.bn254_fq_chip();
        let g1_chip = EccChip::new(&fq_chip);
        
        let g1_points: Vec<_> = g1_points
            .into_iter()
            .map(|point| self.load_bn254_g1_impl(&g1_chip, point).0)
            .collect();
        let sum = g1_chip.sum::<Bn254G1Affine>(self.builder.borrow_mut().main(0), g1_points);
        Bn254G1AffinePoint(sum)
    }

    /// Doesn't range check limbs of g2_point
    fn load_bn254_g2_impl(
        &self,
        g2_chip: &EccChip<Fr, Bn254Fq2Chip<Fr>>,
        point: JsCircuitBn254G2Affine,
    ) -> Bn254G2AffinePoint {
        let fq_chip = g2_chip.field_chip().fp_chip();
        let [x, y] = [point.x, point.y].map(|c| {
            let c0 = self.load_generic_fp_impl::<Bn254Fq>(fq_chip, c.c0);
            let c1 = self.load_generic_fp_impl::<Bn254Fq>(fq_chip, c.c1);
            FieldVector(vec![c0, c1])
        });
        let pt = EcPoint::new(x, y);
        g2_chip.assert_is_on_curve::<Bn254G2Affine>(self.builder.borrow_mut().main(0), &pt);
        Bn254G2AffinePoint(pt)
    }

    pub fn bn254_g1_sub_unequal(
        &self,
        g1_point_1: G1Affine,
        g1_point_2: G1Affine,
    ) -> Bn254G1AffinePoint {
        let fq_chip = self.bn254_fq_chip();
        let g1_chip = EccChip::new(&fq_chip);
        let g1_point_1_loaded: EcPoint<Fr, FqPoint> =
            self.load_bn254_g1_impl(&g1_chip, g1_point_1).0;
        let g1_point_2_loaded: EcPoint<Fr, FqPoint> =
            self.load_bn254_g1_impl(&g1_chip, g1_point_2).0;
        let diff = g1_chip.sub_unequal(
            self.builder.borrow_mut().main(0),
            g1_point_1_loaded,
            g1_point_2_loaded,
            true,
        );
        Bn254G1AffinePoint(diff)
    }

    pub fn bn254_pairing_check(
        &self,
        lhs_g1: Bn254G1AffinePoint,
        lhs_g2: Bn254G2AffinePoint,
        rhs_g1: Bn254G1AffinePoint,
        rhs_g2: Bn254G2AffinePoint,
    ) -> bool {
        let fq_chip = self.bn254_fq_chip();
        let g1_chip = EccChip::new(&fq_chip);
        let mut builder = self.builder.borrow_mut();
        let ctx = builder.main(0);
        let neg_rhs_g1 = g1_chip.negate(ctx, rhs_g1.0);
        let pairing_chip = PairingChip::new(&fq_chip);

        let multi_paired = pairing_chip
            .multi_miller_loop(ctx, vec![(&lhs_g1.0, &lhs_g2.0), (&neg_rhs_g1, &rhs_g2.0)]);
        let fq12_chip = Bn254Fq12Chip::new(&fq_chip);
        let result = fq12_chip.final_exp(ctx, multi_paired);
        let fq12_one = fq12_chip.load_constant(ctx, Bn254Fq12::one());
        let verification_result = fq12_chip.is_equal(ctx, result, fq12_one);
        verification_result.cell.unwrap().offset
    }
}