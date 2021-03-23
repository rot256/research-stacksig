use crate::comm::{CommitKey, Commitment, Randomness, Trapdoor};
use crate::stack::*;
use crate::Side;

use std::io::Write;

use std::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct Compiled<S: Stackable>(pub PhantomData<S>);

#[derive(Debug)]
pub struct CompiledMessageZ<Z: Message> {
    z: Z,
    ck: CommitKey,
    rd: Randomness,
}

impl<M: Message> Message for CompiledMessageZ<M> {
    fn write<W: Write>(&self, writer: &mut W) {
        self.z.write(writer);
        self.ck.write(writer);
        self.rd.write(writer);
    }
}

pub struct CompiledStatement<T>(T, T);

impl<T> CompiledStatement<T> {
    pub fn new(left: T, right: T) -> Self {
        CompiledStatement(left, right)
    }

    fn left(&self) -> &T {
        &self.0
    }

    fn right(&self) -> &T {
        &self.1
    }
}

pub struct CompiledState<A, T> {
    a: A,
    st: T,
    ck: CommitKey,
    td: Trapdoor,
    rd: Randomness,
}

pub struct CompiledWitness<W> {
    side: Side,
    witness: W,
}

impl<W> CompiledWitness<W> {
    pub fn new(witness: W, side: Side) -> CompiledWitness<W> {
        CompiledWitness { witness, side }
    }
}

// if S is a compiled protocol, could pass PreSim into state check

/*
impl<S: Stackable> Compiled<S> {
    fn compile_witness<I: Iterator<Item = Side>>(
        witness: <S as Stackable>::Witness,
        path: &mut I,
    ) -> <Self as Stackable>::Witness {
        let side = path.next().unwrap();

        if !S::is_leaf() {
            S::compile_witness()
        }

        if S::is_leaf() {
            CompiledWitness { side, witness }
        } else {
            unimplemented!()
        }
    }
}
*/

impl<S: Stackable> Stackable for Compiled<S> {
    type State = CompiledState<S::MessageA, S::State>;

    // new witness consists of the old witness and a side: Left/Right
    type Witness = CompiledWitness<S::Witness>;

    // new statement is a 2-tuple
    type Statement = CompiledStatement<S::Statement>;

    // round 1
    type MessageA = Commitment;

    // round 2
    type Challenge = S::Challenge;

    // round 3
    type MessageZ = CompiledMessageZ<S::MessageZ>;

    fn sigma_a<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &Self::Witness,
    ) -> (Self::State, Self::MessageA) {
        let (st, a) = S::sigma_a(rng, &witness.witness);
        let (ck, td) = CommitKey::gen(rng, witness.side);
        let rd = Randomness::random(rng);
        let comm = match witness.side {
            Side::Left => ck.commit::<S::MessageA, S::MessageA>(&rd, (Some(&a), None)),
            Side::Right => ck.commit::<S::MessageA, S::MessageA>(&rd, (None, Some(&a))),
        };

        // first message is just a commitment
        (Self::State { a, st, ck, td, rd }, comm)
    }

    fn sigma_z(
        statement: &Self::Statement,
        witness: &Self::Witness,
        state: &Self::State,
        challenge: &Self::Challenge,
    ) -> Self::MessageZ {
        // compute the active clause
        let (z, ck, rd) = match witness.side {
            Side::Left => {
                // run the real prover on the right
                let z = S::sigma_z(statement.left(), &witness.witness, &state.st, challenge);

                // simulate the right side
                let a_right = S::ehvzk(statement.right(), challenge, &z);

                // equivocate on the right side
                let rd = state.td.equiv(
                    &state.rd,
                    (Some(&state.a), None),
                    (Some(&state.a), Some(&a_right)),
                );

                (z, state.ck, rd)
            }
            Side::Right => {
                // run the real prover on the left
                let z = S::sigma_z(statement.right(), &witness.witness, &state.st, challenge);

                // simulate the right side
                let a_left = S::ehvzk(statement.left(), challenge, &z);

                // equivocate on the left side
                let rd = state.td.equiv(
                    &state.rd,
                    (None, Some(&state.a)),
                    (Some(&a_left), Some(&state.a)),
                );

                (z, state.ck, rd)
            }
        };
        CompiledMessageZ { z, ck, rd }
    }

    fn ehvzk(
        statement: &Self::Statement,
        challenge: &Self::Challenge,
        z: &Self::MessageZ,
    ) -> Self::MessageA {
        let left = S::ehvzk(statement.left(), challenge, &z.z);
        let right = S::ehvzk(statement.right(), challenge, &z.z);
        z.ck.commit(&z.rd, (Some(&left), Some(&right)))
    }
}
