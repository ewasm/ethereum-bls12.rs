extern crate pairing;

use pairing::bls12_381::*;
use pairing::CurveProjective;
use pairing::bls12_381::{Fq2, Fq};
use pairing::PrimeField;
use pairing::CurveAffine;
use pairing::Field;


fn main() {

	// Start with 3 uints
	let (a_x, a_y, b_a_y, b_a_x, b_b_y, b_b_x) = (1u64, 2u64, 3u64, 4u64, 5u64, 6u64);

	// Convert them to Fq
	let a_x_fq = Fq::from_repr(a_x.into()).unwrap();
	let a_y_fq = Fq::from_repr(a_y.into()).unwrap();
	let b_a_y_fq = Fq::from_repr(b_a_y.into()).unwrap();
	let b_a_x_fq = Fq::from_repr(b_a_x.into()).unwrap();
	let b_b_y_fq = Fq::from_repr(b_b_y.into()).unwrap();
	let b_b_x_fq = Fq::from_repr(b_b_x.into()).unwrap();

	let a_fq2 = Fq2 {
		c0: a_x_fq,
		c1: a_y_fq
	};

	let b_a_fq2 = Fq2 {
		c0: b_a_x_fq,
		c1: b_a_y_fq
	};

	let b_b_fq2 = Fq2 {
		c0: b_b_x_fq,
		c1: b_b_y_fq
	};

	// TODO: convert a and b to G1 and G2
	let (a_g1, b_g2) = (
		G1Affine::from(G1::one()),
		G2Affine::from(G2::one()),
	);

	let res = b_g2.pairing_with(&a_g1);

	println!("Result of pairing check: {}", res == Fq12::one());
}
