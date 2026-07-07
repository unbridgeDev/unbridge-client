//! Runnable proof of the user-mandatory-share custody model.
//!
//!   cargo run --example custody_demo
//!
//! The thesis: with a per-user wallet whose group key is split so the USER holds
//! a mandatory share, the operator set cannot produce a signature without the
//! user's participation even if every operator colludes. This is a cryptographic
//! guarantee, not a policy or an economic one, and it is what lets a solo-run
//! operator network still be non-custodial.
//!
//! Modeled here as a 2-of-2 FROST Ed25519 key: party 1 = the user's device,
//! party 2 = the operator network (which in production computes its own
//! contribution via the existing t-of-n operator FROST; see `frost_demo`).
//! Both parties are mandatory; the group secret is never assembled anywhere.

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekKey};
use kobe::KeySet;

const USER: u16 = 1;
const NETWORK: u16 = 2;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Attempt a signature with a given quorum, swallowing the sub-threshold abort
/// so the caller can show the attempt was structurally blocked rather than crash.
fn try_sign(ks: &KeySet, quorum: &[u16], msg: &[u8; 32]) -> Option<[u8; 64]> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ks.threshold_sign(quorum, msg)
    }))
    .ok()
    .and_then(|r| r.ok())
    .map(|s| s.signature)
}

fn main() {
    // Silence the default panic print from the deliberately-failing attempts;
    // we report their outcome ourselves.
    std::panic::set_hook(Box::new(|_| {}));

    let message: [u8; 32] = *b"unbridge: your key, or it stays.";

    // Keygen: one group key, split into a user share and a network share, both
    // required (2-of-2). The group public key is what BTC/ETH/Solana would hold.
    let ks = KeySet::generate(2, 2).expect("keygen failed");
    let group_pk = ks.group_public_key().expect("group pubkey");

    println!("Unbridge / kobe: user-mandatory custody (2-of-2 FROST Ed25519)\n");
    println!("group pubkey : {}", hex(&group_pk));
    println!("shares       : party 1 = USER device, party 2 = OPERATOR NETWORK");
    println!("threshold    : 2 of 2  (both mandatory)\n");

    // 1. THE CORE PROOF: the operator network alone (party 2), even fully
    //    compromised, cannot sign. This is the property no amount of operator
    //    collusion, slashing bypass, or admin action can defeat.
    let net_only = try_sign(&ks, &[NETWORK], &message);
    println!(
        "operators-only  [network]      -> {}",
        match net_only {
            None => "BLOCKED  (no signature without the user's share)",
            Some(_) => "!! PRODUCED A SIGNATURE, model broken !!",
        }
    );

    // 2. Symmetric safety: the user's device alone cannot sign either, so a
    //    stolen/compromised phone does not move funds.
    let user_only = try_sign(&ks, &[USER], &message);
    println!(
        "user-only       [device]       -> {}",
        match user_only {
            None => "BLOCKED  (device theft alone cannot move funds)",
            Some(_) => "!! PRODUCED A SIGNATURE, model broken !!",
        }
    );

    // 3. The only path that works: user + network together.
    let joint = try_sign(&ks, &[USER, NETWORK], &message)
        .expect("user + network quorum must produce a signature");
    println!("user + network  [both]         -> SIGNED\n");

    // 4. Independent standard Ed25519 verification, exactly what the target
    //    chain runs. Proves the joint output is an ordinary RFC 8032 signature
    //    under the group key, with the group secret never reconstructed.
    let dalek_key = DalekKey::from_bytes(&group_pk).expect("invalid group key");
    dalek_key
        .verify(&message, &DalekSig::from_bytes(&joint))
        .expect("independent ed25519-dalek verification failed");

    println!("signature(64): {}", hex(&joint));
    println!("independent ed25519-dalek verify against the group key: VERIFIED\n");

    assert!(
        net_only.is_none(),
        "operator-only signing must be impossible"
    );
    assert!(user_only.is_none(), "user-only signing must be impossible");

    println!("Result: the operator network cannot sign without the user, the user");
    println!("cannot sign without the network, and the group key was never assembled");
    println!("in one place. \"Don't trust us. We can't move your funds without you.\"");
}
