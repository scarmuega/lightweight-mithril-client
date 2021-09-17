use crate::ev_lt_phi;
use crate::msp::{Msp, MspMvk};
use crate::merkle_tree::MerkleTree;
use crate::stm::{StmSig, StmParameters};
use super::Index;

use std::collections::HashSet;
use std::iter::FromIterator;

pub trait Proof {
    fn prove(avk: &MerkleTree, ivk: &MspMvk, msg: &[u8], sigs: &[StmSig], indices: &[Index], evals: &[u64]) -> Self;
    fn verify(&self, params: &StmParameters, total_stake: u64, avk: &MerkleTree, ivk: &MspMvk, msg: &[u8]) -> bool;
}

// Proof system that simply concatenates the witness
#[derive(Clone)]
pub struct ConcatProof {
    sigs: Vec<StmSig>,
    indices: Vec<Index>,
    evals: Vec<u64>,
}

impl Proof for ConcatProof {
    fn prove(_avk: &MerkleTree, _ivk: &MspMvk, _msg: &[u8], sigs: &[StmSig], indices: &[Index], evals: &[u64]) -> Self {
        Self {
            sigs: sigs.to_vec(),
            indices: indices.to_vec(),
            evals: evals.to_vec(),
        }
    }

    fn verify(&self, params: &StmParameters, total_stake: u64, avk: &MerkleTree, ivk: &MspMvk, msg: &[u8]) -> bool
    {
        // ivk = Prod(1..k, mvk[i])
        let ivk_check = ivk.0 == self.sigs.iter().map(|s| s.pk.mvk.0).sum();

        // \forall i. index[i] <= m
        let index_bound_check = self.indices.iter().fold(true, |r, i| r && i <= &params.m);

        // \forall i. \forall j. (i == j || index[i] != index[j])
        let index_uniq_check =
               HashSet::<Index>::from_iter(self.indices.iter().cloned()).len()
            == self.indices.len();

        // k-sized quorum
        let quorum_check =
            params.k as usize <= self.sigs.len()   &&
            params.k as usize <= self.evals.len()  &&
            params.k as usize <= self.indices.len();

        // \forall i : [0..k]. path[i] is a witness for (mvk[i]), stake[i] in avk
        let path_check =
            self.sigs[0..params.k as usize].iter().fold(true, |r, sig| {
                r && avk.check(&(sig.pk, sig.stake), sig.party, &sig.path)
            });

        // \forall i : [1..k]. ev[i] = MSP.Eval(msg, index[i], sig[i])
        let msp_evals =
            self.indices[0..params.k as usize]
            .iter()
            .zip(self.sigs[0..params.k as usize].iter())
            .map(|(idx, sig)| {
                let msgp = avk.concat_with_msg(msg);
                Msp::eval(&msgp, *idx, &sig.sigma)
            });
        let eval_check =
            self.evals[0..params.k as usize]
                  .iter()
                  .zip(msp_evals)
                  .fold(true, |r, (ev, msp_e)| r && *ev == msp_e);

        // \forall i : [1..k]. ev[i] <= phi(stake_i)
        let eval_stake_check =
            self.evals[0..params.k as usize]
                  .iter()
                  .zip(&self.sigs[0..params.k as usize])
                  .fold(true, |r, (ev, sig)| r && ev_lt_phi(params.phi_f, *ev, sig.stake, total_stake));

        ivk_check &&
        index_bound_check &&
        index_uniq_check &&
        path_check &&
        quorum_check &&
        eval_check &&
        eval_stake_check
    }
}
