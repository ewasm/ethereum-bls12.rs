extern crate pairing;
extern crate parity_bytes;
extern crate rustc_hex;

use pairing::bls12_381::{Bls12, G1Affine, G2Affine, Fq12};
use pairing::{Engine, CurveAffine, EncodedPoint, Field};

use std::io::{self, Read};

use rustc_hex::FromHex;



use parity_bytes::BytesRef;

#[derive(Debug)]
pub struct Error(String);

impl From<String> for Error {
	fn from(val: String) -> Self {
		Error(val)
	}
}

impl From<io::Error> for Error {
	fn from(val: io::Error) -> Self {
		Error(val.to_string())
	}
}

fn read_bls12_pairing_input(mut input: &[u8]) -> Result<Vec<(<G1Affine as CurveAffine>::Prepared, <G2Affine as CurveAffine>::Prepared)>, Error> {
	let mut g1_repr = <G1Affine as CurveAffine>::Compressed::empty();
    let mut g2_repr = <G2Affine as CurveAffine>::Compressed::empty();

    let length = input.len();

    if length % 144 != 0 {
    	return Err(Error::from("wrong size".to_string()));
    }

    let mut res = vec![];

    for _ in 0..length / 144 {
    	input.read_exact(g1_repr.as_mut())?;

        let a = g1_repr
                .into_affine()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;


        input.read_exact(g2_repr.as_mut())?;

        let b = g2_repr
                .into_affine()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|e| if e.is_zero() {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "point at infinity"))
                } else {
                    Ok(e)
                })?;

        res.push((a.prepare(), b.prepare()));
    }

	Ok(res)
}

pub fn bls12_pairing(input: &[u8], output: &mut BytesRef) -> Result<(), Error> {
	let points = read_bls12_pairing_input(input);

	let true_res = FromHex::from_hex("\
			0000000000000000000000000000000000000000000000000000000000000001"
		).unwrap();

	let false_res = FromHex::from_hex("\
			0000000000000000000000000000000000000000000000000000000000000000"
		).unwrap();


	match points {
		Ok(points) => {
			let refs: Vec<_> = points.iter().map(|(ref a, ref b)| (a, b)).collect();
			if compute_pairing_check(refs.iter()) {
				output.write(0, &true_res);
			} else {
				output.write(0, &false_res);
			}
			Ok(())
		},
		Err(err) => Err(err)
	}
}

fn compute_pairing_check<'a, I>(i: I) -> bool
    where
        I: IntoIterator<
            Item = &'a (
                &'a <G1Affine as CurveAffine>::Prepared,
                &'a <G2Affine as CurveAffine>::Prepared,
            ),
        >,
    {
	Bls12::final_exponentiation(&Bls12::miller_loop(i)).unwrap() == Fq12::one()
}

#[cfg(test)]
mod tests {

	use pairing::bls12_381::{G1, G2};
	use pairing::CurveProjective;
	use super::*;
	use rustc_hex::FromHex;

	#[test]
	fn empty() {
		assert!(compute_pairing_check(vec![]))
	}

	#[test]
	fn random() {
		assert!(!compute_pairing_check(vec![&(&G1Affine::from(G1::one()).prepare(), &G2Affine::from(G2::one()).prepare())]))
	}

	#[test]
	fn read_empty() {
		let input = FromHex::from_hex("").unwrap();

		let mut output = vec![0u8; 32];

		let expected = FromHex::from_hex("\
			0000000000000000000000000000000000000000000000000000000000000001"
		).unwrap();

		bls12_pairing(&input[..], &mut BytesRef::Fixed(&mut output[..])).unwrap();
		assert_eq!(output, expected);
	}

	#[test]
	fn read_two_pairs_true() {
		// check that e(1, 1) * e(-1, 1) = 1
		let a1 = G1Affine::from(G1::one()).into_compressed();
		let a2 = G2Affine::from(G2::one()).into_compressed();
		let mut minus_one = G1::one();
		minus_one.negate();
		let b1 = G1Affine::from(minus_one).into_compressed();
		let b2 = G2Affine::from(G2::one()).into_compressed();

		let input: Vec<_> = vec![a1.as_ref(), a2.as_ref(), b1.as_ref(), b2.as_ref()].into_iter().flat_map(|s| s.into_iter()).map(|x| *x).collect();

		let mut output = vec![0u8; 32];

		let expected = FromHex::from_hex("\
			0000000000000000000000000000000000000000000000000000000000000001"
		).unwrap();

		bls12_pairing(&input[..], &mut BytesRef::Fixed(&mut output[..])).unwrap();
		assert_eq!(output, expected);
	}

	#[test]
	fn read_two_pairs_false() {
		// check that e(1, 1) * e(1, 1) != 1
		let a1 = G1Affine::from(G1::one()).into_compressed();
		let a2 = G2Affine::from(G2::one()).into_compressed();
		let b1 = G1Affine::from(G1::one()).into_compressed();
		let b2 = G2Affine::from(G2::one()).into_compressed();

		let input: Vec<_> = vec![a1.as_ref(), a2.as_ref(), b1.as_ref(), b2.as_ref()].into_iter().flat_map(|s| s.into_iter()).map(|x| *x).collect();

		let mut output = vec![0u8; 32];

		let expected = FromHex::from_hex("\
			0000000000000000000000000000000000000000000000000000000000000000"
		).unwrap();
		
		bls12_pairing(&input[..], &mut BytesRef::Fixed(&mut output[..])).unwrap();
		assert_eq!(output, expected);
	}
}
