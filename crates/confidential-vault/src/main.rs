//! Amount-hiding milestone: drive the RE-ENABLED Token-2022 confidential balances
//! on devnet with the current-generation stack (spl-token-2022 11 +
//! solana-zk-sdk 6.0.1). The older spl-token 3.4.1 CLI called the dead ZK program
//! address; the sample's pinned solana-zk-sdk 4.0.0 predates the Fiat-Shamir
//! transcript fix that shipped when the program was re-enabled on 2026-06-29, so
//! its proofs are rejected on devnet (Agave 4.1.0). Version 6.0.1 carries the
//! fixed transcript.
//!
//! Load-bearing detail for a FROST-owned confidential account: the account's
//! ElGamal view key is generated INDEPENDENTLY (new_rand), NOT derived from the
//! owner's signature. A FROST group key signs non-deterministically (the shared
//! nonce is fresh per session), so the usual derive-from-signature convention
//! would produce a different view key every time and lock the group out of its
//! own balance. An independent view key, split across the team out of band, is
//! what lets a threshold key own a confidential account. Here the owner is a
//! normal wallet; swapping in FROST for the owner authority is the mechanical
//! follow-up.

use std::error::Error;

use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction};
use solana_system_interface::instruction::create_account;
use solana_zk_sdk::{
    encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    zk_elgamal_proof_program::build_pubkey_validity_proof_data,
};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::{configure_account, deposit, initialize_mint as ct_init_mint},
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, ExtensionType, StateWithExtensionsOwned,
    },
    instruction::{initialize_mint, mint_to, reallocate},
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;

const DEFAULT_RPC: &str = "https://api.devnet.solana.com";
const DECIMALS: u8 = 2;
const MINT_AMOUNT: u64 = 100_000;
const DEPOSIT_AMOUNT: u64 = 42_000;

fn load_payer() -> Keypair {
    let path = std::env::var("UNBRIDGE_KEYPAIR_PATH").unwrap_or_else(|_| {
        format!(
            "{}/.config/solana/id.json",
            std::env::var("HOME").expect("HOME must be set")
        )
    });
    let bytes: Vec<u8> = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read keypair at {path}: {e}")),
    )
    .expect("keypair file must be a JSON byte array");
    Keypair::try_from(bytes.as_slice()).expect("keypair bytes must decode")
}

fn send(
    client: &RpcClient,
    ixs: &[solana_sdk::instruction::Instruction],
    payer: &Keypair,
    extra: &[&Keypair],
) -> String {
    let bh = client.get_latest_blockhash().expect("blockhash");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &signers, bh);
    client.send_and_confirm_transaction(&tx).expect("send tx").to_string()
}

fn hex16(b: &[u8]) -> String {
    b.iter().take(16).map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let rpc = std::env::var("UNBRIDGE_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC.to_string());
    let client = RpcClient::new_with_commitment(rpc, CommitmentConfig::confirmed());
    let payer = load_payer();
    let owner = &payer;
    let program_id = spl_token_2022::id();
    println!("payer/owner: {}", payer.pubkey());

    // 1. Create a confidential-transfer mint.
    let mint = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;
    let ixs = vec![
        create_account(&payer.pubkey(), &mint.pubkey(), rent, space as u64, &program_id),
        ct_init_mint(&program_id, &mint.pubkey(), Some(payer.pubkey()), true, None)?,
        initialize_mint(&program_id, &mint.pubkey(), &payer.pubkey(), Some(&payer.pubkey()), DECIMALS)?,
    ];
    let sig = send(&client, &ixs, &payer, &[&mint]);
    println!("1. confidential mint {} (tx {}...)", mint.pubkey(), &sig[..16]);

    // 2. Configure the account with an INDEPENDENT view key + 6.0.1 pubkey-validity proof.
    let ata =
        get_associated_token_address_with_program_id(&owner.pubkey(), &mint.pubkey(), &program_id);
    let elgamal = ElGamalKeypair::new_rand();
    let aes = AeKey::new_rand();
    let decryptable_zero = aes.encrypt(0);
    let proof = build_pubkey_validity_proof_data(&elgamal)?;

    let mut ixs = vec![
        create_associated_token_account(&payer.pubkey(), &owner.pubkey(), &mint.pubkey(), &program_id),
        reallocate(
            &program_id,
            &ata,
            &payer.pubkey(),
            &owner.pubkey(),
            &[&owner.pubkey()],
            &[ExtensionType::ConfidentialTransferAccount],
        )?,
    ];
    ixs.extend(configure_account(
        &program_id,
        &ata,
        &mint.pubkey(),
        &decryptable_zero.into(),
        65536,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(1i8.try_into().unwrap(), &proof),
    )?);
    let sig = send(&client, &ixs, &payer, &[]);
    println!(
        "2. account configured, independent view key, 6.0.1 pubkey-validity proof accepted (tx {}...)",
        &sig[..16]
    );

    // 3. Mint public tokens, then deposit into the confidential (encrypted) balance.
    let sig = send(
        &client,
        &[mint_to(&program_id, &mint.pubkey(), &ata, &payer.pubkey(), &[&payer.pubkey()], MINT_AMOUNT)?],
        &payer,
        &[],
    );
    println!("3. minted {} public base units (tx {}...)", MINT_AMOUNT, &sig[..16]);
    let sig = send(
        &client,
        &[deposit(&program_id, &ata, &mint.pubkey(), DEPOSIT_AMOUNT, DECIMALS, &owner.pubkey(), &[&owner.pubkey()])?],
        &payer,
        &[],
    );
    println!("4. deposited {} into the confidential balance (tx {}...)", DEPOSIT_AMOUNT, &sig[..16]);

    // 4. Read back: the balance is an ElGamal ciphertext on-chain.
    let data = client.get_account_data(&ata)?;
    let state = StateWithExtensionsOwned::<Account>::unpack(data)?;
    let cta = state.get_extension::<ConfidentialTransferAccount>()?;
    let pending_lo: [u8; 64] = bytemuck::cast(cta.pending_balance_lo);
    println!(
        "\n   on-chain confidential balance (ElGamal ciphertext, first 16 bytes): {}",
        hex16(&pending_lo)
    );
    println!(
        "   the ElGamal view key that can decrypt it is held off-chain (here new_rand; in the product, split across the team)"
    );
    println!(
        "   account: https://explorer.solana.com/address/{}?cluster=devnet",
        ata
    );

    println!(
        "\nOK: current-gen crates drive the re-enabled confidential program on devnet; the 6.0.1 proof is accepted, the account is owned by a normal key today, and the balance sits on-chain as ciphertext. FROST-owner is the mechanical swap."
    );
    Ok(())
}
