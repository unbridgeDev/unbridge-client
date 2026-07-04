//! On-chain account layout and PDA seeds for Distin.
//!
//! Every persistent account derives `InitSpace` so the rent reservation is
//! computed from the field set itself (`8 + T::INIT_SPACE`, where 8 is the
//! Anchor account discriminator). The byte breakdown is documented per account.

use anchor_lang::prelude::*;

/// PDA seed for the singleton protocol config: `[PROTOCOL_SEED]`.
pub const PROTOCOL_SEED: &[u8] = b"protocol";
/// PDA seed for the bonded-collateral vault: `[BOND_VAULT_SEED, protocol]`.
pub const BOND_VAULT_SEED: &[u8] = b"bond_vault";
/// PDA seed for the slash pool: `[SLASH_POOL_SEED, protocol]`.
pub const SLASH_POOL_SEED: &[u8] = b"slash_pool";
/// PDA seed for an operator: `[OPERATOR_SEED, protocol, authority]`.
pub const OPERATOR_SEED: &[u8] = b"operator";
/// PDA seed for a signing request: `[REQUEST_SEED, protocol, request_id_le]`.
pub const REQUEST_SEED: &[u8] = b"request";
/// PDA seed for a partial signature: `[PARTIAL_SEED, request, operator]`.
pub const PARTIAL_SEED: &[u8] = b"partial";
/// PDA seed for an authorized requester wallet: `[WALLET_SEED, protocol, authority]`.
pub const WALLET_SEED: &[u8] = b"wallet";

/// Threshold-signature scheme branched per destination VM family.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureScheme {
    /// FROST Schnorr over Ed25519 — SVM / Aptos / Sui style chains.
    FrostEd25519,
    /// GG20-style threshold ECDSA over secp256k1 — EVM / BTC / Tron style chains.
    Gg20Secp256k1,
}

/// Destination virtual-machine family the aggregate signature targets.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum TargetVm {
    Svm,
    Evm,
    Tron,
    Cosmos,
    Bitcoin,
}

/// Lifecycle state of a signing request.
#[derive(AnchorSerialize, AnchorDeserialize, InitSpace, Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestStatus {
    Pending,
    Aggregated,
    Cancelled,
    Expired,
}

/// Singleton protocol configuration and global accounting.
///
/// Seeds: `[PROTOCOL_SEED]`.
/// Space (INIT_SPACE): admin 32 + pending_admin 32 + bond_mint 32 + bond_vault 32
/// + slash_pool 32 + lst_price_feed 32 + threshold_bps 2 + min_bond 8
/// + unbonding_slots 8 + request_fee 8 + max_validity_slots 8 + operator_count 4
/// + total_bonded 8 + request_nonce 8 + paused 1 + bump 1 = 248 bytes (+8 disc).
#[account]
#[derive(InitSpace)]
pub struct Protocol {
    /// Current admin authority.
    pub admin: Pubkey,
    /// Nominated successor admin (two-step handover); default until set.
    pub pending_admin: Pubkey,
    /// Token-2022 LST mint accepted as bonded collateral.
    pub bond_mint: Pubkey,
    /// Protocol-owned vault holding active bonds.
    pub bond_vault: Pubkey,
    /// Protocol-owned pool collecting slashed collateral.
    pub slash_pool: Pubkey,
    /// Pyth price account for valuing the LST bond in SOL terms.
    pub lst_price_feed: Pubkey,
    /// Fraction of total staked weight required to finalize a request (bps).
    pub threshold_bps: u16,
    /// Minimum bond an operator must post to join the signing set.
    pub min_bond: u64,
    /// Slots an operator must wait between unbonding and withdrawal.
    pub unbonding_slots: u64,
    /// Lamport fee charged per signing request.
    pub request_fee: u64,
    /// Upper bound on a request's validity window, in slots.
    pub max_validity_slots: u64,
    /// Number of operators currently in the active signing set.
    pub operator_count: u32,
    /// Sum of active operators' staked economic weight.
    pub total_bonded: u64,
    /// Monotonic counter seeding request PDAs.
    pub request_nonce: u64,
    /// Emergency pause flag.
    pub paused: bool,
    /// PDA bump.
    pub bump: u8,
}

/// A bonded signing operator.
///
/// Seeds: `[OPERATOR_SEED, protocol, authority]`.
/// Space (INIT_SPACE): protocol 32 + authority 32 + group_pubkey 33
/// + bonded_amount 8 + stake_weight 8 + partials_submitted 8 + slash_count 4
/// + jailed 1 + unbonding_at 8 + joined_slot 8 + bump 1 = 143 bytes (+8 disc).
#[account]
#[derive(InitSpace)]
pub struct Operator {
    /// Owning protocol.
    pub protocol: Pubkey,
    /// Operator authority (signer for submissions and lifecycle actions).
    pub authority: Pubkey,
    /// Compressed group public key / FROST public-share identifier.
    pub group_pubkey: [u8; 33],
    /// Raw bonded LST amount held in the vault.
    pub bonded_amount: u64,
    /// SOL-denominated economic weight derived from the bond via the oracle.
    pub stake_weight: u64,
    /// Lifetime count of partial signatures submitted.
    pub partials_submitted: u64,
    /// Number of times this operator has been slashed.
    pub slash_count: u32,
    /// Whether the operator is jailed (cannot sign new requests).
    pub jailed: bool,
    /// Slot at which unbonding completes; 0 while actively bonded.
    pub unbonding_at: u64,
    /// Slot the operator joined.
    pub joined_slot: u64,
    /// PDA bump.
    pub bump: u8,
}

/// A user's cross-VM signing intent and its aggregation progress.
///
/// Seeds: `[REQUEST_SEED, protocol, request_id_le]`.
/// Space (INIT_SPACE): protocol 32 + requester 32 + request_id 8 + scheme 1
/// + target_vm 1 + target_chain_id 8 + message_hash 32 + threshold 2
/// + partials_collected 2 + stake_weight_collected 8 + required_stake_weight 8
/// + created_slot 8 + expiry_slot 8 + status 1 + aggregate_sig 64 + bump 1
/// = 224 bytes (+8 disc).
#[account]
#[derive(InitSpace)]
pub struct SigningRequest {
    /// Owning protocol.
    pub protocol: Pubkey,
    /// Account that posted the intent (rent refund destination on close).
    pub requester: Pubkey,
    /// Monotonic request id used in the PDA seed.
    pub request_id: u64,
    /// Signature scheme required for the destination VM.
    pub scheme: SignatureScheme,
    /// Destination VM family.
    pub target_vm: TargetVm,
    /// Destination chain id (EVM chain id, Cosmos chain index, etc.).
    pub target_chain_id: u64,
    /// 32-byte hash of the message/transaction to be signed off-chain.
    pub message_hash: [u8; 32],
    /// Minimum number of distinct partial signatures required.
    pub threshold: u16,
    /// Partial signatures collected so far.
    pub partials_collected: u16,
    /// Staked economic weight collected so far.
    pub stake_weight_collected: u64,
    /// Economic-security target snapshotted at creation (bps of total bonded).
    pub required_stake_weight: u64,
    /// Slot the request was created.
    pub created_slot: u64,
    /// Slot after which the request can no longer be fulfilled.
    pub expiry_slot: u64,
    /// Lifecycle state.
    pub status: RequestStatus,
    /// Running aggregate signature accumulator, published on finalization.
    pub aggregate_sig: [u8; 64],
    /// PDA bump.
    pub bump: u8,
}

/// An authorized requester identity for wallet-gated signing requests.
///
/// While the protocol operates a single shared group key, WHO may have
/// messages signed with it is an explicit allowlist: registration is
/// admin-gated because the key is protocol-owned. When per-user group keys
/// land, registration moves into the keygen flow and becomes self-serve.
///
/// Seeds: `[WALLET_SEED, protocol, authority]`.
/// Space (INIT_SPACE): protocol 32 + authority 32 + registered_slot 8 + bump 1
/// = 73 bytes (+8 disc).
#[account]
#[derive(InitSpace)]
pub struct Wallet {
    /// Owning protocol.
    pub protocol: Pubkey,
    /// The authority allowed to post wallet-gated signing requests.
    pub authority: Pubkey,
    /// Slot the wallet was registered.
    pub registered_slot: u64,
    /// PDA bump.
    pub bump: u8,
}

/// A single operator's partial-signature contribution to a request.
///
/// Seeds: `[PARTIAL_SEED, request, operator]` — uniqueness prevents double submit.
/// Space (INIT_SPACE): request 32 + operator 32 + scheme 1 + share 64
/// + submitted_slot 8 + stake_weight 8 + bump 1 = 146 bytes (+8 disc).
#[account]
#[derive(InitSpace)]
pub struct PartialSignature {
    /// Request this share contributes to.
    pub request: Pubkey,
    /// Operator that submitted the share.
    pub operator: Pubkey,
    /// Scheme of the share (must match the request scheme).
    pub scheme: SignatureScheme,
    /// 64-byte partial-signature share material.
    pub share: [u8; 64],
    /// Slot the share was submitted.
    pub submitted_slot: u64,
    /// Staked weight credited for this contribution.
    pub stake_weight: u64,
    /// PDA bump.
    pub bump: u8,
}
