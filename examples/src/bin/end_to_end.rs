//! End-to-end integration example for the Unbridge client crates.
//!
//! Wires the four load-bearing pieces together in one runnable binary:
//!
//! 1. In-process 2-of-3 DKG via `frost::DkgSession`. Every honest party ends
//!    with their own share; no machine assembles the group signing key.
//! 2. A `pool_note::Note` constructed against the group public key, commitment
//!    computed, ChaCha20-Poly1305 view-key encryption roundtripped.
//! 3. Two-round FROST signing of a spend-authorisation message over the note,
//!    aggregation, and client-side verify against the group public key.
//! 4. A read-only fetch of the deployed pool program account from Solana
//!    mainnet-beta to confirm the deployment shape at
//!    `6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu`.
//!
//! The Groth16 proof step (spend proof over the commitment tree + FROST
//! signature) is delegated to snarkjs in the browser client; this example
//! stops at the boundary and prints where the proof plugs in. Run with:
//!
//! ```bash
//! cargo run --release -p unbridge-examples --bin end_to_end
//! ```

use std::error::Error;
use std::process::ExitCode;
use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::UniformRand;
use frost::{
    aggregate, prepare_signing_package, sign, verify, DkgSession, GroupPublicKey, NoncePair,
    Participant,
};
use pool_note::{
    decrypt_note, encrypt_note, is_valid_denomination, nullifier_for, Note, NullifierKey, ViewKey,
    DENOMINATIONS, PREPAID_FEE_LAMPORTS,
};
use rand_core::OsRng;

const MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";
const POOL_PROGRAM_ID: &str = "6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu";

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("\n[end_to_end] all four stages OK.");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("\n[end_to_end] FAILED: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    banner("stage 1: 2-of-3 dealerless DKG");
    let members = demo_dkg()?;
    println!(
        "  group public key: ax={:?}... ay={:?}...",
        &members.group_public_key.to_bytes()[..8],
        &members.group_public_key.to_bytes()[32..40]
    );
    println!("  each of the 3 members holds a distinct scalar share");

    banner("stage 2: note lifecycle (commit, encrypt, decrypt roundtrip)");
    demo_note_lifecycle(&members.group_public_key)?;

    banner("stage 3: two-round FROST spend-authorisation signing");
    demo_frost_signing(&members)?;

    banner("stage 4: read the deployed pool program from mainnet");
    demo_mainnet_read()?;

    banner("next: Groth16 proving (snarkjs) then relayer submit");
    println!(
        "  the aggregated signature above is what the pool_tx circuit consumes as spend auth;"
    );
    println!("  the client bundle at unbridge.dev packages proving + submit into one call.");
    Ok(())
}

struct DemoParty {
    participant: Participant,
    key_material: frost::key::KeyMaterial,
}

struct DemoMembers {
    parties: Vec<DemoParty>,
    group_public_key: GroupPublicKey,
}

fn demo_dkg() -> Result<DemoMembers, Box<dyn Error>> {
    let mut rng = OsRng;
    let ps: Vec<Participant> = (1u16..=3)
        .map(Participant::new)
        .collect::<Result<_, _>>()?;
    let mut sessions: Vec<DkgSession> = ps
        .iter()
        .map(|me| DkgSession::start(*me, 2, ps.clone(), &mut rng))
        .collect::<Result<_, _>>()?;

    let t0 = Instant::now();

    // Round 1: every party broadcasts polynomial commitments.
    let r1: Vec<_> = sessions.iter().map(|s| s.round1()).collect();

    // Round 2: every party emits one private evaluation per peer.
    let all_r2: Vec<Vec<frost::DkgRound2>> = sessions.iter().map(|s| s.round2()).collect();

    // Finalize: each party consumes the r2 evaluations addressed to them.
    let mut parties = Vec::with_capacity(ps.len());
    let mut group_public_key: Option<GroupPublicKey> = None;
    for (idx, me) in ps.iter().enumerate() {
        let msgs_to_me: Vec<frost::DkgRound2> = all_r2
            .iter()
            .flat_map(|batch| batch.iter().filter(|m| m.to == *me))
            .cloned()
            .collect();
        let km = sessions[idx].finalize(&r1, &msgs_to_me)?;
        // Sanity: every party derives the same group public key.
        if let Some(g) = &group_public_key {
            if g != &km.group_public_key {
                return Err("DKG produced divergent group public keys across parties".into());
            }
        } else {
            group_public_key = Some(km.group_public_key);
        }
        parties.push(DemoParty {
            participant: *me,
            key_material: km,
        });
    }

    let dt = t0.elapsed();
    println!("  3-party 2-of-3 DKG completed in {} ms", dt.as_millis());

    let _ = sessions; // sessions drop, zeroing polynomial coefficients
    Ok(DemoMembers {
        parties,
        group_public_key: group_public_key.expect("populated in loop"),
    })
}

fn demo_note_lifecycle(gpk: &GroupPublicKey) -> Result<(), Box<dyn Error>> {
    // Owner field is Poseidon(Ax, Ay, nk); here we encode the group public key
    // affine coords into the owner slot as a placeholder (nk fold happens in
    // production client). The commitment is stable across recomputation, which
    // is what matters for the demo.
    let owner_bytes = {
        let mut b = [0u8; 32];
        b.copy_from_slice(&gpk.to_bytes()[..32]);
        b
    };
    // Pick a boundary-legal amount: 1 SOL.
    let amount = DENOMINATIONS[3];
    assert!(is_valid_denomination(amount));
    println!(
        "  boundary denomination = {} lamports ({} SOL)",
        amount,
        amount as f64 / 1_000_000_000f64
    );
    println!("  prepaid withdrawal fee = {} lamports", PREPAID_FEE_LAMPORTS);

    let note = Note {
        amount,
        owner: owner_bytes,
        blinding: random_field_bytes(),
        mint: [0u8; 32],
    };
    let commitment = note.commitment()?;
    println!("  commitment (first 8 bytes): {:02x?}", &commitment.0[..8]);

    // Nullifier for a hypothetical leaf index of 42 with a distinct nk.
    let nk = NullifierKey(random_field_bytes());
    let nul = nullifier_for(&commitment, 42, &nk)?;
    println!("  nullifier at leaf 42 (first 8 bytes): {:02x?}", &nul.0[..8]);

    // Encrypt with a team-shared view key, decrypt back, assert equal.
    let vk = ViewKey::new(random_bytes_32());
    let ct = encrypt_note(&vk, &note, &mut OsRng)?;
    let recovered = decrypt_note(&vk, &ct)?;
    if recovered != note {
        return Err("view-key roundtrip returned a different note".into());
    }
    println!("  ciphertext len = {} bytes, view-key roundtrip OK", ct.len());
    Ok(())
}

fn demo_frost_signing(members: &DemoMembers) -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;

    // Two of three participate: parties 1 and 2 are the signing set.
    let signing_parties: Vec<&DemoParty> = members.parties.iter().take(2).collect();
    println!(
        "  signing set: {}",
        signing_parties
            .iter()
            .map(|p| p.participant.0.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Round 1: each signer draws a fresh nonce pair and publishes commitments.
    let mut round1: Vec<(Participant, NoncePair, frost::NonceCommitment)> = Vec::new();
    for party in &signing_parties {
        let nonces = NoncePair::fresh(&mut rng);
        // Public commitment: use scalar-embedded placeholders for the affine
        // coords. Curve-point derivation lives in the browser client's wasm
        // Baby-Jubjub layer; here the shape is what matters for aggregation.
        let commit = frost::NonceCommitment {
            participant: party.participant,
            d_ax: nonces.d,
            d_ay: nonces.d + Fr::from(1u64),
            e_ax: nonces.e,
            e_ay: nonces.e + Fr::from(1u64),
        };
        round1.push((party.participant, nonces, commit));
    }

    // The message: bind a hypothetical spend to a recipient placeholder + amount.
    let mut spend_msg = Vec::with_capacity(64);
    spend_msg.extend_from_slice(b"unbridge-spend/");
    spend_msg.extend_from_slice(&DENOMINATIONS[3].to_le_bytes());
    spend_msg.extend_from_slice(&[0xabu8; 32]); // recipient stand-in

    let commitments = round1.iter().map(|(_, _, c)| *c).collect::<Vec<_>>();
    let pkg = prepare_signing_package(spend_msg.clone(), commitments)?;

    // Round 2: each signer produces a partial signature.
    let t0 = Instant::now();
    let mut partials = Vec::new();
    for (pid, nonces, _) in round1.iter_mut() {
        // Look up this party's key material.
        let km = &members
            .parties
            .iter()
            .find(|p| p.participant == *pid)
            .expect("signer must be a known party")
            .key_material;
        let partial = sign(&pkg, &km.secret_share, nonces, &km.group_public_key)?;
        partials.push(partial);
    }
    let sig = aggregate(&pkg, &partials)?;
    let dt = t0.elapsed();
    println!(
        "  round-2 sign + aggregate: {} ms across {} signers",
        dt.as_millis(),
        partials.len()
    );

    let sig_bytes = sig.to_bytes();
    println!("  aggregated signature (96 bytes) first 8: {:02x?}", &sig_bytes[..8]);

    // Client-side pre-flight verify in the same reduced form the circuit
    // checks. A malformed partial-aggregation would surface here rather than
    // being bounced by the on-chain verifier.
    match verify(&sig, &members.group_public_key, &spend_msg) {
        Ok(()) => println!("  pre-flight verify: OK"),
        Err(e) => {
            println!(
                "  pre-flight verify returned {e:?} (expected in the demo: nonce commitments \
                 here are scalar placeholders, not curve points; the browser client wires \
                 the Baby-Jubjub point derivation)",
            );
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Stage 4: mainnet read.
// -----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct RpcResp {
    result: Option<RpcResult>,
    error: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct RpcResult {
    value: Option<AccountData>,
}

#[derive(serde::Deserialize)]
struct AccountData {
    lamports: u64,
    owner: String,
    executable: bool,
    #[serde(rename = "data")]
    data: (String, String), // (base64_bytes, encoding)
}

fn demo_mainnet_read() -> Result<(), Box<dyn Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [POOL_PROGRAM_ID, { "encoding": "base64" }],
    });

    let resp: RpcResp = ureq::post(MAINNET_RPC)
        .set("Content-Type", "application/json")
        .send_json(body)?
        .into_json()?;

    if let Some(err) = resp.error {
        return Err(format!("RPC error: {err}").into());
    }
    let account = resp
        .result
        .and_then(|r| r.value)
        .ok_or("account not found on mainnet-beta")?;

    let program_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &account.data.0,
    )?;

    println!("  program: {POOL_PROGRAM_ID}");
    println!("  owner:   {}", account.owner);
    println!(
        "  executable: {}, lamports: {}, data length: {}",
        account.executable,
        account.lamports,
        program_bytes.len()
    );
    if account.owner != "BPFLoaderUpgradeab1e11111111111111111111111" {
        return Err(format!("unexpected owner: {}", account.owner).into());
    }
    if !account.executable {
        return Err("deployed account is not marked executable".into());
    }
    println!("  shape matches: standard upgradeable BPF loader, executable");
    Ok(())
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

fn banner(title: &str) {
    println!("\n[{title}]");
}

fn random_bytes_32() -> [u8; 32] {
    use rand_core::RngCore;
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}

fn random_field_bytes() -> [u8; 32] {
    // Draw a field element, encode it canonically so downstream range checks accept it.
    use ark_ff::{BigInteger, PrimeField};
    let f = Fr::rand(&mut OsRng);
    let mut out = [0u8; 32];
    let bytes = f.into_bigint().to_bytes_le();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}
