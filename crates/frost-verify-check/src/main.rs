mod errors;
mod groth16;
mod data;

use groth16::{Groth16Verifier, Groth16Verifyingkey};

fn main() {
    let vk = Groth16Verifyingkey {
        nr_pubinputs: data::PUBLIC_INPUTS.len(),
        vk_alpha_g1: data::VK_ALPHA,
        vk_beta_g2: data::VK_BETA,
        vk_gamme_g2: data::VK_GAMMA,
        vk_delta_g2: data::VK_DELTA,
        vk_ic: &data::VK_IC,
    };

    let mut v = Groth16Verifier::<{ data::PUBLIC_INPUTS.len() }>::new(
        &data::PROOF_A,
        &data::PROOF_B,
        &data::PROOF_C,
        &data::PUBLIC_INPUTS,
        &vk,
    )
    .expect("verifier construction");

    match v.verify() {
        Ok(true) => println!(">>> ON-CHAIN VERIFIER (alt_bn128) accepts our pool proof: VERIFIED ✓"),
        Ok(false) => println!(">>> verifier returned false"),
        Err(e) => println!(">>> verification error: {e:?}"),
    }
}
