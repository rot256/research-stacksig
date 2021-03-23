#![feature(associated_type_defaults)]

mod comm;
mod compiler;
mod fiat;
mod schnorr;
mod stack;

#[derive(Copy, Clone)]
pub enum Side {
    Left,
    Right,
}

type S2 = compiler::Compiled<schnorr::Schnorr>;
type S4 = compiler::Compiled<S2>;
type S8 = compiler::Compiled<S4>;
type S16 = compiler::Compiled<S8>;
type S32 = compiler::Compiled<S16>;
type S64 = compiler::Compiled<S32>;
type S128 = compiler::Compiled<S64>;
type S256 = compiler::Compiled<S128>;
type S512 = compiler::Compiled<S256>;
type S1024 = compiler::Compiled<S512>;
type S2048 = compiler::Compiled<S1024>;

type Sig1024 = fiat::SignatureScheme<S1024>;
type Sig2048 = fiat::SignatureScheme<S2048>;

use rand_core::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use compiler::*;

use schnorr::Schnorr;

use stack::{Message, Stackable};

const LEVELS: usize = 11;

macro_rules! compile {
    ($pks:expr, $sk:expr) => {{
        let sk = CompiledWitness::new($sk, Side::Left);
        let len = $pks.len() / 2;
        let mut pk: Vec<_> = Vec::with_capacity(len);
        let mut pk_I = $pks.into_iter();
        for i in 0..len {
            let l = pk_I.next().unwrap();
            let r = pk_I.next().unwrap();
            pk.push(CompiledStatement::new(l, r));
        }
        (pk, sk)
    }};
}

fn main() {
    let sk = Scalar::random(&mut OsRng);
    let mut pk: Vec<RistrettoPoint> = Vec::with_capacity(1 << LEVELS);
    pk.push(&sk * &RISTRETTO_BASEPOINT_TABLE);
    for _ in 1..(1 << LEVELS) {
        pk.push(&Scalar::random(&mut OsRng) * &RISTRETTO_BASEPOINT_TABLE);
    }

    let (pk, sk) = compile!(pk, sk);
    let (pk, sk) = compile!(pk, sk);

    let (pk, sk) = compile!(pk, sk);
    let (pk, sk) = compile!(pk, sk);

    let (pk, sk) = compile!(pk, sk);
    let (pk, sk) = compile!(pk, sk);

    let (pk, sk) = compile!(pk, sk);
    let (pk, sk) = compile!(pk, sk);

    let (pk, sk) = compile!(pk, sk);
    let (pk, sk) = compile!(pk, sk);

    let (pk, sk) = compile!(pk, sk);

    assert_eq!(pk.len(), 1);

    for _ in 0..100 {
        let sig = Sig2048::sign(&mut OsRng, &sk, &pk[0], &[]);

        println!("{}", sig.size());
    }

    //Sig2::sign(&mut OsRng);
}
