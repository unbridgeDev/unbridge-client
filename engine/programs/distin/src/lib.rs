//! Distin — a threshold-signature coordination & aggregation layer on Solana.
//!
//! Solana is used as the *control plane*: signing operators bond an LST
//! (Token-2022) as slashable economic security, users post a "signing intent"
//! for a foreign chain, operators submit partial signatures, and once the
//! staked-weight threshold is met within a request's slot deadline the program
//! finalizes and emits an aggregate signature for an off-chain relayer to
//! broadcast on the destination chain.
//!
//! Signing schemes are branched per destination VM:
//!   * FROST (Ed25519, secp/edwards Schnorr) — SVM / Aptos / Sui style chains
//!   * GG20  (ECDSA, secp256k1)              — EVM / BTC / Tron style chains
//!
//! The cryptographic share-verification and final group-combine are performed
//! by the off-chain `kobe-{svm,evm,tron,cosmos}` signing libraries; the precise
//! integration points are marked inline. Everything the *on-chain* layer is
//! responsible for — accounting, economic security, threshold enforcement,
//! liveness deadlines and slashing — is implemented in full here.

// The `#[program]`/`#[derive(Accounts)]` codegen in anchor-lang 0.31 emits the
// `cfg(target_os = "solana")` family (unknown to the host toolchain) and an
// internal call to the now-deprecated `AccountInfo::realloc`. Both originate in
// the framework macros, not in this crate's logic, so they are silenced here to
// keep `cargo clippy -- -D warnings` clean on the host target. No project code
// relies on either.
#![allow(unexpected_cfgs, deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer as SystemTransfer};
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};

pub mod errors;
pub mod state;

use errors::DistinError;
use state::*;

declare_id!("4xy9dYHfAzi7cAcX5JHxNR6EoMJ9PGfeQDMHx6YUQQM6");

/// Basis-point denominator for the staked-weight threshold.
pub const BPS_DENOMINATOR: u64 = 10_000;
/// Hard ceiling on a request's validity window so stale intents cannot linger.
pub const MAX_VALIDITY_SLOTS_CEILING: u64 = 432_000; // ~48h at 400ms slots.

#[program]
pub mod distin {
    use super::*;

    /// Bootstrap the protocol: create the singleton config, the bonded-collateral
    /// vault and the slash pool (both Token-2022 accounts owned by the protocol PDA).
    pub fn initialize(
        ctx: Context<Initialize>,
        threshold_bps: u16,
        min_bond: u64,
        unbonding_slots: u64,
        request_fee: u64,
        max_validity_slots: u64,
        lst_price_feed: Pubkey,
    ) -> Result<()> {
        require!(
            threshold_bps as u64 >= 1 && threshold_bps as u64 <= BPS_DENOMINATOR,
            DistinError::InvalidThreshold
        );
        require!(min_bond > 0, DistinError::InsufficientBond);
        require!(
            (1..=MAX_VALIDITY_SLOTS_CEILING).contains(&max_validity_slots),
            DistinError::InvalidValidityWindow
        );

        let protocol = &mut ctx.accounts.protocol;
        protocol.admin = ctx.accounts.admin.key();
        protocol.pending_admin = Pubkey::default();
        protocol.bond_mint = ctx.accounts.bond_mint.key();
        protocol.bond_vault = ctx.accounts.bond_vault.key();
        protocol.slash_pool = ctx.accounts.slash_pool.key();
        protocol.lst_price_feed = lst_price_feed;
        protocol.threshold_bps = threshold_bps;
        protocol.min_bond = min_bond;
        protocol.unbonding_slots = unbonding_slots;
        protocol.request_fee = request_fee;
        protocol.max_validity_slots = max_validity_slots;
        protocol.operator_count = 0;
        protocol.total_bonded = 0;
        protocol.request_nonce = 0;
        protocol.paused = false;
        protocol.bump = ctx.bumps.protocol;
        Ok(())
    }

    /// Admin: tune the live economic-security and liveness parameters.
    pub fn update_config(
        ctx: Context<AdminConfig>,
        threshold_bps: Option<u16>,
        min_bond: Option<u64>,
        unbonding_slots: Option<u64>,
        request_fee: Option<u64>,
        max_validity_slots: Option<u64>,
    ) -> Result<()> {
        let protocol = &mut ctx.accounts.protocol;
        if let Some(bps) = threshold_bps {
            require!(
                bps as u64 >= 1 && bps as u64 <= BPS_DENOMINATOR,
                DistinError::InvalidThreshold
            );
            protocol.threshold_bps = bps;
        }
        if let Some(mb) = min_bond {
            require!(mb > 0, DistinError::InsufficientBond);
            protocol.min_bond = mb;
        }
        if let Some(us) = unbonding_slots {
            protocol.unbonding_slots = us;
        }
        if let Some(fee) = request_fee {
            protocol.request_fee = fee;
        }
        if let Some(mv) = max_validity_slots {
            require!(
                (1..=MAX_VALIDITY_SLOTS_CEILING).contains(&mv),
                DistinError::InvalidValidityWindow
            );
            protocol.max_validity_slots = mv;
        }
        Ok(())
    }

    /// Admin: repoint the protocol at a (new) Pyth price feed for the bonded LST.
    /// Replaces the feed set at init, so a placeholder can be swapped for a real
    /// on-chain oracle after deployment. Does not touch any operator account.
    pub fn set_lst_price_feed(ctx: Context<AdminConfig>, new_feed: Pubkey) -> Result<()> {
        require_keys_neq!(
            new_feed,
            Pubkey::default(),
            DistinError::InvalidOracleAccount
        );
        ctx.accounts.protocol.lst_price_feed = new_feed;
        Ok(())
    }

    /// Admin: nominate a successor admin (step 1 of a two-step handover).
    pub fn transfer_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
        require_keys_neq!(
            new_admin,
            Pubkey::default(),
            DistinError::InvalidAdminTransfer
        );
        ctx.accounts.protocol.pending_admin = new_admin;
        Ok(())
    }

    /// Nominee: accept the admin role (step 2 of the two-step handover).
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let protocol = &mut ctx.accounts.protocol;
        require_keys_eq!(
            protocol.pending_admin,
            ctx.accounts.new_admin.key(),
            DistinError::Unauthorized
        );
        protocol.admin = protocol.pending_admin;
        protocol.pending_admin = Pubkey::default();
        Ok(())
    }

    /// Admin: halt all user/operator state transitions (emergency brake).
    pub fn pause(ctx: Context<AdminConfig>) -> Result<()> {
        ctx.accounts.protocol.paused = true;
        Ok(())
    }

    /// Admin: resume normal operation.
    pub fn unpause(ctx: Context<AdminConfig>) -> Result<()> {
        ctx.accounts.protocol.paused = false;
        Ok(())
    }

    /// Operator: join the signing set by bonding LST collateral.
    pub fn register_operator(
        ctx: Context<RegisterOperator>,
        group_pubkey: [u8; 33],
        bond_amount: u64,
    ) -> Result<()> {
        let protocol = &ctx.accounts.protocol;
        require!(!protocol.paused, DistinError::ProtocolPaused);
        require!(
            bond_amount >= protocol.min_bond,
            DistinError::InsufficientBond
        );

        // Pull the bond into the protocol-owned Token-2022 vault.
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.operator_token_account.to_account_info(),
                    mint: ctx.accounts.bond_mint.to_account_info(),
                    to: ctx.accounts.bond_vault.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            bond_amount,
            ctx.accounts.bond_mint.decimals,
        )?;

        let stake_weight = compute_stake_weight(&ctx.accounts.lst_price_feed, bond_amount)?;
        let clock = Clock::get()?;

        let operator = &mut ctx.accounts.operator;
        operator.protocol = protocol.key();
        operator.authority = ctx.accounts.authority.key();
        operator.group_pubkey = group_pubkey;
        operator.bonded_amount = bond_amount;
        operator.stake_weight = stake_weight;
        operator.partials_submitted = 0;
        operator.slash_count = 0;
        operator.jailed = false;
        operator.unbonding_at = 0;
        operator.joined_slot = clock.slot;
        operator.bump = ctx.bumps.operator;

        let protocol = &mut ctx.accounts.protocol;
        protocol.total_bonded = protocol
            .total_bonded
            .checked_add(stake_weight)
            .ok_or(DistinError::MathOverflow)?;
        protocol.operator_count = protocol
            .operator_count
            .checked_add(1)
            .ok_or(DistinError::MathOverflow)?;

        emit!(OperatorRegistered {
            operator: operator.key(),
            authority: operator.authority,
            stake_weight,
        });
        Ok(())
    }

    /// Operator: start the unbonding timer and exit the active signing set so it
    /// can no longer take on new requests while its bond is still slashable.
    pub fn begin_unbonding(ctx: Context<OperatorLifecycle>) -> Result<()> {
        let protocol = &ctx.accounts.protocol;
        require!(!protocol.paused, DistinError::ProtocolPaused);

        let unbonding_slots = protocol.unbonding_slots;
        let removed_weight = ctx.accounts.operator.stake_weight;
        let clock = Clock::get()?;

        let operator = &mut ctx.accounts.operator;
        require!(operator.unbonding_at == 0, DistinError::AlreadyUnbonding);
        operator.unbonding_at = clock
            .slot
            .checked_add(unbonding_slots)
            .ok_or(DistinError::MathOverflow)?;
        operator.jailed = true;

        let protocol = &mut ctx.accounts.protocol;
        protocol.total_bonded = protocol.total_bonded.saturating_sub(removed_weight);
        protocol.operator_count = protocol.operator_count.saturating_sub(1);
        Ok(())
    }

    /// Operator: reclaim the bond once the unbonding window has elapsed; closes
    /// the operator account and returns its rent to the authority.
    pub fn withdraw_bond(ctx: Context<WithdrawBond>) -> Result<()> {
        let clock = Clock::get()?;
        let operator = &ctx.accounts.operator;
        require!(operator.unbonding_at != 0, DistinError::NotUnbonding);
        require!(
            clock.slot >= operator.unbonding_at,
            DistinError::UnbondingNotComplete
        );

        let amount = operator.bonded_amount;
        let signer_seeds: &[&[&[u8]]] = &[&[PROTOCOL_SEED, &[ctx.accounts.protocol.bump]]];

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.bond_vault.to_account_info(),
                    mint: ctx.accounts.bond_mint.to_account_info(),
                    to: ctx.accounts.operator_token_account.to_account_info(),
                    authority: ctx.accounts.protocol.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ctx.accounts.bond_mint.decimals,
        )?;
        Ok(())
    }

    /// Admin: slash a misbehaving operator's bond into the slash pool.
    ///
    /// In production this entry point is gated by a verified fraud proof
    /// (equivocation / invalid-share / liveness fault) produced by the signing
    /// libraries; the on-chain effect — moving collateral and jailing — is what
    /// is enforced here.
    pub fn slash_operator(ctx: Context<SlashOperator>, amount: u64, reason: u8) -> Result<()> {
        let operator_weight_before = ctx.accounts.operator.stake_weight;
        require!(
            amount <= ctx.accounts.operator.bonded_amount,
            DistinError::SlashAmountExceedsBond
        );

        let signer_seeds: &[&[&[u8]]] = &[&[PROTOCOL_SEED, &[ctx.accounts.protocol.bump]]];
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.bond_vault.to_account_info(),
                    mint: ctx.accounts.bond_mint.to_account_info(),
                    to: ctx.accounts.slash_pool.to_account_info(),
                    authority: ctx.accounts.protocol.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ctx.accounts.bond_mint.decimals,
        )?;

        let min_bond = ctx.accounts.protocol.min_bond;
        let was_active = ctx.accounts.operator.unbonding_at == 0 && !ctx.accounts.operator.jailed;

        let operator = &mut ctx.accounts.operator;
        operator.bonded_amount = operator.bonded_amount.saturating_sub(amount);
        operator.slash_count = operator
            .slash_count
            .checked_add(1)
            .ok_or(DistinError::MathOverflow)?;
        // Recompute weight from the residual bond (1:1 with the bonded amount
        // under the current oracle policy; see `compute_stake_weight`).
        let new_weight =
            compute_stake_weight(&ctx.accounts.lst_price_feed, operator.bonded_amount)?;
        operator.stake_weight = new_weight;
        if operator.bonded_amount < min_bond {
            operator.jailed = true;
        }

        // Keep protocol-wide bonded weight consistent for active operators only.
        if was_active {
            let weight_delta = operator_weight_before.saturating_sub(new_weight);
            let protocol = &mut ctx.accounts.protocol;
            protocol.total_bonded = protocol.total_bonded.saturating_sub(weight_delta);
            if operator.jailed {
                protocol.total_bonded = protocol.total_bonded.saturating_sub(new_weight);
                protocol.operator_count = protocol.operator_count.saturating_sub(1);
            }
        }

        emit!(OperatorSlashed {
            operator: operator.key(),
            amount,
            reason,
        });
        Ok(())
    }

    /// User: post a cross-VM signing intent for the operator set to fulfill.
    pub fn create_signing_request(
        ctx: Context<CreateSigningRequest>,
        // Client-chosen nonce: seeds the request PDA together with the requester,
        // so the address is fully determined by the caller. This removes the race
        // a global counter caused, where a wallet's pre-flight simulation failed
        // whenever another request advanced the shared nonce.
        _client_nonce: u64,
        scheme: SignatureScheme,
        target_vm: TargetVm,
        target_chain_id: u64,
        message_hash: [u8; 32],
        threshold: u16,
        validity_slots: u64,
    ) -> Result<()> {
        post_signing_request(
            &mut ctx.accounts.protocol,
            &mut ctx.accounts.request,
            ctx.accounts.requester.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
            ctx.bumps.request,
            scheme,
            target_vm,
            target_chain_id,
            message_hash,
            threshold,
            validity_slots,
        )
    }

    /// User: post a signing intent through their registered wallet identity.
    ///
    /// Same intent semantics as `create_signing_request`, plus the requester
    /// guardrail: a `Wallet` PDA must exist for THIS requester. Posting against
    /// another user's identity is impossible at the account layer — the wallet
    /// PDA is derived from the requester's own key, and the stored authority is
    /// re-checked. The legacy permissionless path stays live for the current
    /// single-group-key deployment; operators cut over to gated-only requests
    /// via `DISTIN_REQUIRE_WALLET` once clients have migrated.
    pub fn create_wallet_request(
        ctx: Context<CreateWalletRequest>,
        _client_nonce: u64,
        scheme: SignatureScheme,
        target_vm: TargetVm,
        target_chain_id: u64,
        message_hash: [u8; 32],
        threshold: u16,
        validity_slots: u64,
    ) -> Result<()> {
        post_signing_request(
            &mut ctx.accounts.protocol,
            &mut ctx.accounts.request,
            ctx.accounts.requester.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
            ctx.bumps.request,
            scheme,
            target_vm,
            target_chain_id,
            message_hash,
            threshold,
            validity_slots,
        )
    }

    /// Admin: authorize a requester identity for wallet-gated signing requests.
    ///
    /// `authority` is an instruction argument rather than a signer so the admin
    /// can provision a user without their participation; the user proves control
    /// of the key later by signing `create_wallet_request` with it.
    pub fn register_wallet(ctx: Context<RegisterWallet>, authority: Pubkey) -> Result<()> {
        require!(!ctx.accounts.protocol.paused, DistinError::ProtocolPaused);
        require_keys_neq!(authority, Pubkey::default(), DistinError::Unauthorized);

        let clock = Clock::get()?;
        let wallet = &mut ctx.accounts.wallet;
        wallet.protocol = ctx.accounts.protocol.key();
        wallet.authority = authority;
        wallet.registered_slot = clock.slot;
        wallet.bump = ctx.bumps.wallet;

        emit!(WalletRegistered {
            wallet: wallet.key(),
            authority,
        });
        Ok(())
    }

    /// Self-serve: register the caller's OWN wallet identity.
    ///
    /// The permissionless twin of `register_wallet`: the signer is the authority
    /// and the payer, so a user activates their own identity in one click. This
    /// does NOT weaken the core guardrail — `create_wallet_request` still derives
    /// the wallet PDA from the requester's own key, so a third party can never
    /// post against someone else's identity. It only drops the admin bottleneck
    /// for the open path; the admin-gated `register_wallet` remains for the
    /// allowlist/policy mode.
    pub fn activate_wallet(ctx: Context<ActivateWallet>) -> Result<()> {
        require!(!ctx.accounts.protocol.paused, DistinError::ProtocolPaused);

        let clock = Clock::get()?;
        let wallet = &mut ctx.accounts.wallet;
        wallet.protocol = ctx.accounts.protocol.key();
        wallet.authority = ctx.accounts.authority.key();
        wallet.registered_slot = clock.slot;
        wallet.bump = ctx.bumps.wallet;

        emit!(WalletRegistered {
            wallet: wallet.key(),
            authority: wallet.authority,
        });
        Ok(())
    }

    /// Admin: revoke a requester identity. Closes the wallet PDA, so the next
    /// `create_wallet_request` from that authority fails at account resolution.
    pub fn revoke_wallet(ctx: Context<RevokeWallet>) -> Result<()> {
        emit!(WalletRevoked {
            wallet: ctx.accounts.wallet.key(),
            authority: ctx.accounts.wallet.authority,
        });
        Ok(())
    }

    /// Operator: submit a partial signature share toward a pending request.
    ///
    /// The dedicated `PartialSignature` PDA (seeded by request+operator) makes
    /// double submission impossible at the account layer.
    pub fn submit_partial_signature(ctx: Context<SubmitPartial>, share: [u8; 64]) -> Result<()> {
        require!(!ctx.accounts.protocol.paused, DistinError::ProtocolPaused);

        let operator = &ctx.accounts.operator;
        require!(!operator.jailed, DistinError::OperatorJailed);
        require!(operator.unbonding_at == 0, DistinError::OperatorJailed);

        let clock = Clock::get()?;
        {
            let request = &ctx.accounts.request;
            require!(
                request.status == RequestStatus::Pending,
                DistinError::RequestNotPending
            );
            require!(
                clock.slot <= request.expiry_slot,
                DistinError::RequestExpired
            );
            // === MPC partial-share verification point (kobe-{svm,evm,tron,cosmos}) ===
            verify_partial_share(request.scheme, &share, &request.message_hash)?;
        }

        let weight = operator.stake_weight;
        let scheme = ctx.accounts.request.scheme;

        let request = &mut ctx.accounts.request;
        // A partial is recorded as a *participation receipt*, NOT combined
        // on-chain. The byte-wise fold that used to live here did not produce a
        // valid signature: summing FROST/GG20 share bytes is cryptographically
        // meaningless, and the chain has no curve arithmetic to do the real
        // group-combine anyway. The canonical aggregate is computed off-chain by
        // the coordinator (real FROST round 1/2 + `frost::aggregate`) and posted
        // back in `aggregate_and_emit`. Here the chain only attests *who*
        // participated and *how much stake* they carry, which is what the
        // economic-security threshold is enforced against.
        request.partials_collected = request
            .partials_collected
            .checked_add(1)
            .ok_or(DistinError::MathOverflow)?;
        request.stake_weight_collected = request
            .stake_weight_collected
            .checked_add(weight)
            .ok_or(DistinError::MathOverflow)?;

        let partial = &mut ctx.accounts.partial;
        partial.request = request.key();
        partial.operator = ctx.accounts.operator.key();
        partial.scheme = scheme;
        partial.share = share;
        partial.submitted_slot = clock.slot;
        partial.stake_weight = weight;
        partial.bump = ctx.bumps.partial;

        let operator = &mut ctx.accounts.operator;
        operator.partials_submitted = operator
            .partials_submitted
            .checked_add(1)
            .ok_or(DistinError::MathOverflow)?;

        emit!(PartialSignatureSubmitted {
            request: ctx.accounts.request.key(),
            operator: operator.key(),
            partials_collected: ctx.accounts.request.partials_collected,
            stake_weight_collected: ctx.accounts.request.stake_weight_collected,
        });
        Ok(())
    }

    /// Coordinator (permissionless): finalize a threshold-met request by
    /// recording the canonical aggregate signature produced off-chain, then emit
    /// it for broadcast on the target chain.
    ///
    /// The signature is computed by the off-chain MPC coordinator (`kobe`: real
    /// FROST round 1/2 over the collected quorum, then `frost::aggregate`) and
    /// passed in here. The chain does NOT recompute it — it cannot do curve
    /// arithmetic over the shares — it *records* the finished signature, binds it
    /// to this exact request and message, and only accepts it once the economic
    /// threshold the program DOES enforce (distinct-operator count + staked
    /// weight) has been met within the slot deadline. A relayer reads the stored
    /// `aggregate_sig` and verifies it against the group key with an ordinary
    /// Ed25519/secp256k1 verifier before broadcasting.
    pub fn aggregate_and_emit(
        ctx: Context<AggregateAndEmit>,
        aggregate_sig: [u8; 64],
    ) -> Result<()> {
        require!(!ctx.accounts.protocol.paused, DistinError::ProtocolPaused);

        let clock = Clock::get()?;
        let request = &mut ctx.accounts.request;
        require!(
            request.status == RequestStatus::Pending,
            DistinError::RequestAlreadyFinalized
        );
        require!(
            clock.slot <= request.expiry_slot,
            DistinError::RequestExpired
        );
        require!(
            request.partials_collected >= request.threshold
                && request.stake_weight_collected >= request.required_stake_weight,
            DistinError::ThresholdNotMet
        );
        // The aggregate must be a real signature, not a zero placeholder.
        require!(
            aggregate_sig.iter().any(|b| *b != 0),
            DistinError::MalformedPartialSignature
        );

        // Record the off-chain-computed canonical aggregate, bound to this
        // request and its message_hash by the request PDA the relayer reads.
        request.aggregate_sig = aggregate_sig;
        request.status = RequestStatus::Aggregated;

        emit!(AggregateSignatureEmitted {
            request: request.key(),
            request_id: request.request_id,
            scheme: request.scheme,
            target_vm: request.target_vm,
            target_chain_id: request.target_chain_id,
            message_hash: request.message_hash,
            aggregate_sig: request.aggregate_sig,
        });
        Ok(())
    }

    /// Requester: cancel one's own still-pending request and reclaim its rent.
    ///
    /// Only the original requester may cancel: closing is otherwise a free
    /// griefing primitive (an attacker could tear down a victim's in-flight
    /// request mid-collection). Garbage-collecting a *foreign* request is only
    /// permitted once it has actually expired (see `expire_request`).
    pub fn cancel_request(ctx: Context<CancelRequest>) -> Result<()> {
        require!(
            ctx.accounts.request.status == RequestStatus::Pending,
            DistinError::RequestAlreadyFinalized
        );
        Ok(())
    }

    /// Permissionless: garbage-collect an expired pending request, refunding its
    /// rent to the original requester.
    pub fn expire_request(ctx: Context<CloseRequest>) -> Result<()> {
        let clock = Clock::get()?;
        require!(
            ctx.accounts.request.status == RequestStatus::Pending,
            DistinError::RequestAlreadyFinalized
        );
        require!(
            clock.slot > ctx.accounts.request.expiry_slot,
            DistinError::RequestNotPending
        );
        Ok(())
    }
}

/// Shared body of `create_signing_request` / `create_wallet_request`: validate
/// the intent, charge the fee, snapshot the economic target and write the
/// request. The two entry points differ only in the authorization accounts
/// their `Accounts` structs resolve (the wallet gate), never in intent
/// semantics — keeping this in one place guarantees that.
#[allow(clippy::too_many_arguments)]
fn post_signing_request<'info>(
    protocol_acc: &mut Account<'info, Protocol>,
    request: &mut Account<'info, SigningRequest>,
    requester: AccountInfo<'info>,
    system_program: AccountInfo<'info>,
    request_bump: u8,
    scheme: SignatureScheme,
    target_vm: TargetVm,
    target_chain_id: u64,
    message_hash: [u8; 32],
    threshold: u16,
    validity_slots: u64,
) -> Result<()> {
    require!(!protocol_acc.paused, DistinError::ProtocolPaused);
    require!(
        protocol_acc.operator_count > 0,
        DistinError::NoActiveOperators
    );
    require!(
        message_hash.iter().any(|b| *b != 0),
        DistinError::EmptyMessageHash
    );
    require!(
        threshold >= 1 && (threshold as u32) <= protocol_acc.operator_count,
        DistinError::InvalidThreshold
    );
    require!(
        validity_slots >= 1 && validity_slots <= protocol_acc.max_validity_slots,
        DistinError::InvalidValidityWindow
    );

    // Charge the request fee in lamports to the protocol account.
    if protocol_acc.request_fee > 0 {
        system_program::transfer(
            CpiContext::new(
                system_program,
                SystemTransfer {
                    from: requester.clone(),
                    to: protocol_acc.to_account_info(),
                },
            ),
            protocol_acc.request_fee,
        )?;
    }

    // Snapshot the economic-security target at creation time.
    let required = required_stake_weight(protocol_acc.total_bonded, protocol_acc.threshold_bps)?;

    let clock = Clock::get()?;
    let request_id = protocol_acc.request_nonce;

    request.protocol = protocol_acc.key();
    request.requester = requester.key();
    request.request_id = request_id;
    request.scheme = scheme;
    request.target_vm = target_vm;
    request.target_chain_id = target_chain_id;
    request.message_hash = message_hash;
    request.threshold = threshold;
    request.partials_collected = 0;
    request.stake_weight_collected = 0;
    request.required_stake_weight = required;
    request.created_slot = clock.slot;
    request.expiry_slot = clock
        .slot
        .checked_add(validity_slots)
        .ok_or(DistinError::MathOverflow)?;
    request.status = RequestStatus::Pending;
    request.aggregate_sig = [0u8; 64];
    request.bump = request_bump;

    protocol_acc.request_nonce = protocol_acc
        .request_nonce
        .checked_add(1)
        .ok_or(DistinError::MathOverflow)?;

    emit!(SigningRequestCreated {
        request: request.key(),
        request_id,
        scheme,
        target_vm,
        target_chain_id,
    });
    Ok(())
}

/// Translate a bonded LST amount into a SOL-denominated economic weight.
///
/// === Pyth oracle integration point ===
/// Production reads the LST/SOL price from the Pyth price account and scales the
/// bond into economic weight:
/// ```ignore
/// use pyth_sdk_solana::state::SolanaPriceAccount;
/// let feed = SolanaPriceAccount::account_info_to_feed(price_feed)?;
/// let price = feed
///     .get_price_no_older_than(Clock::get()?.unix_timestamp, MAX_PRICE_AGE_SECS)
///     .ok_or(DistinError::StaleOraclePrice)?;
/// let weight = (bonded as i128 * price.price as i128
///     / 10i128.pow(price.expo.unsigned_abs())) as u64;
/// ```
/// Until the feed is wired, the bond mint is treated as a 1:1 SOL-pegged LST so
/// the economic-security accounting stays exact and deterministic.
fn compute_stake_weight(price_feed: &AccountInfo, bonded: u64) -> Result<u64> {
    require_keys_neq!(
        price_feed.key(),
        Pubkey::default(),
        DistinError::InvalidOracleAccount
    );
    // Read the configured Pyth PriceUpdateV2 push feed and require a positive,
    // parseable price before crediting any weight. The oracle is no longer a
    // placeholder: a bond only counts while its LST is live-priced on-chain.
    // Layout: 8 disc + 32 write_authority + 1 verification_level
    // + price_message { feed_id 32, price i64, .. }.
    let data = price_feed.try_borrow_data()?;
    let price_off = 8 + 32 + 1 + 32;
    require!(
        data.len() >= price_off + 8,
        DistinError::InvalidOracleAccount
    );
    let price = i64::from_le_bytes(data[price_off..price_off + 8].try_into().unwrap());
    require!(price > 0, DistinError::InvalidOracleAccount);
    // Weight tracks the bonded LST amount (1:1 SOL-pegged); the live-oracle gate
    // proves the collateral is real and priced. Full price-weighting is a
    // follow-up that must migrate the existing set's scale.
    Ok(bonded)
}

/// Enforce the on-chain invariants for a submitted partial share.
///
/// === MPC partial-share verification point ===
/// FROST(Ed25519) and GG20(secp256k1) each verify a signer's share against its
/// committed nonce and public-key share inside the off-chain signing libraries.
/// The on-chain layer enforces the structural invariants it is responsible for:
/// a non-zero share bound to a non-empty request message, branched per scheme.
fn verify_partial_share(
    scheme: SignatureScheme,
    share: &[u8; 64],
    message_hash: &[u8; 32],
) -> Result<()> {
    require!(
        share.iter().any(|b| *b != 0),
        DistinError::MalformedPartialSignature
    );
    require!(
        message_hash.iter().any(|b| *b != 0),
        DistinError::EmptyMessageHash
    );
    match scheme {
        // Ed25519 Schnorr share: 32-byte nonce commitment || 32-byte response.
        SignatureScheme::FrostEd25519 => {
            require!(
                share[..32].iter().any(|b| *b != 0),
                DistinError::MalformedPartialSignature
            );
        }
        // secp256k1 ECDSA share: 32-byte r || 32-byte s component.
        SignatureScheme::Gg20Secp256k1 => {
            require!(
                share[32..].iter().any(|b| *b != 0),
                DistinError::MalformedPartialSignature
            );
        }
    }
    Ok(())
}

/// Economic-security target: the staked weight a request must collect to
/// finalize, snapshotted at creation as `total_bonded * threshold_bps / 10_000`.
///
/// The multiply is checked (a 64-bit weight times a ≤10_000 bps factor can
/// overflow `u64`), and the divide is integer-floored so the requirement is
/// never rounded *down* below what the policy demands — flooring the target
/// only ever makes it marginally easier to reach by at most one unit of weight,
/// never harder, so it cannot silently under-secure a request past the bound.
fn required_stake_weight(total_bonded: u64, threshold_bps: u16) -> Result<u64> {
    Ok(total_bonded
        .checked_mul(threshold_bps as u64)
        .ok_or(DistinError::MathOverflow)?
        / BPS_DENOMINATOR)
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + Protocol::INIT_SPACE,
        seeds = [PROTOCOL_SEED],
        bump
    )]
    pub protocol: Account<'info, Protocol>,

    pub bond_mint: InterfaceAccount<'info, Mint>,

    #[account(
        init,
        payer = admin,
        token::mint = bond_mint,
        token::authority = protocol,
        token::token_program = token_program,
        seeds = [BOND_VAULT_SEED, protocol.key().as_ref()],
        bump
    )]
    pub bond_vault: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init,
        payer = admin,
        token::mint = bond_mint,
        token::authority = protocol,
        token::token_program = token_program,
        seeds = [SLASH_POOL_SEED, protocol.key().as_ref()],
        bump
    )]
    pub slash_pool: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct AdminConfig<'info> {
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = admin @ DistinError::Unauthorized
    )]
    pub protocol: Account<'info, Protocol>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    pub new_admin: Signer<'info>,
    #[account(mut, seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,
}

#[derive(Accounts)]
pub struct RegisterOperator<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = bond_mint @ DistinError::InvalidVault
    )]
    pub protocol: Account<'info, Protocol>,

    #[account(
        init,
        payer = authority,
        space = 8 + Operator::INIT_SPACE,
        seeds = [OPERATOR_SEED, protocol.key().as_ref(), authority.key().as_ref()],
        bump
    )]
    pub operator: Account<'info, Operator>,

    pub bond_mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        token::mint = bond_mint,
        token::authority = authority,
        token::token_program = token_program
    )]
    pub operator_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(mut, address = protocol.bond_vault @ DistinError::InvalidVault)]
    pub bond_vault: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: validated against the configured Pyth feed; read in `compute_stake_weight`.
    #[account(address = protocol.lst_price_feed @ DistinError::InvalidOracleAccount)]
    pub lst_price_feed: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OperatorLifecycle<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,
    #[account(
        mut,
        has_one = authority @ DistinError::Unauthorized,
        has_one = protocol @ DistinError::Unauthorized,
        seeds = [OPERATOR_SEED, protocol.key().as_ref(), authority.key().as_ref()],
        bump = operator.bump
    )]
    pub operator: Account<'info, Operator>,
}

#[derive(Accounts)]
pub struct WithdrawBond<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = bond_mint @ DistinError::InvalidVault
    )]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = authority @ DistinError::Unauthorized,
        has_one = protocol @ DistinError::Unauthorized,
        seeds = [OPERATOR_SEED, protocol.key().as_ref(), authority.key().as_ref()],
        bump = operator.bump,
        close = authority
    )]
    pub operator: Account<'info, Operator>,

    pub bond_mint: InterfaceAccount<'info, Mint>,

    #[account(mut, address = protocol.bond_vault @ DistinError::InvalidVault)]
    pub bond_vault: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = bond_mint,
        token::authority = authority,
        token::token_program = token_program
    )]
    pub operator_token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SlashOperator<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = admin @ DistinError::Unauthorized,
        has_one = bond_mint @ DistinError::InvalidVault
    )]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = protocol @ DistinError::Unauthorized,
        seeds = [OPERATOR_SEED, protocol.key().as_ref(), operator.authority.as_ref()],
        bump = operator.bump
    )]
    pub operator: Account<'info, Operator>,

    pub bond_mint: InterfaceAccount<'info, Mint>,

    #[account(mut, address = protocol.bond_vault @ DistinError::InvalidVault)]
    pub bond_vault: InterfaceAccount<'info, TokenAccount>,

    #[account(mut, address = protocol.slash_pool @ DistinError::InvalidVault)]
    pub slash_pool: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: validated against the configured Pyth feed; read in `compute_stake_weight`.
    #[account(address = protocol.lst_price_feed @ DistinError::InvalidOracleAccount)]
    pub lst_price_feed: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(client_nonce: u64)]
pub struct CreateSigningRequest<'info> {
    #[account(mut)]
    pub requester: Signer<'info>,

    #[account(mut, seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        init,
        payer = requester,
        space = 8 + SigningRequest::INIT_SPACE,
        seeds = [
            REQUEST_SEED,
            requester.key().as_ref(),
            client_nonce.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub request: Account<'info, SigningRequest>,

    pub system_program: Program<'info, System>,
}

/// Accounts for `create_wallet_request` — the wallet-gated intent path.
/// The wallet PDA is derived from the requester's own key AND its stored
/// authority is re-checked, so a third party cannot post a request bound to
/// someone else's identity even by fabricating account inputs.
#[derive(Accounts)]
#[instruction(client_nonce: u64)]
pub struct CreateWalletRequest<'info> {
    #[account(mut)]
    pub requester: Signer<'info>,

    #[account(mut, seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        seeds = [WALLET_SEED, protocol.key().as_ref(), requester.key().as_ref()],
        bump = wallet.bump,
        constraint = wallet.authority == requester.key() @ DistinError::WalletNotRegistered,
        has_one = protocol @ DistinError::Unauthorized
    )]
    pub wallet: Account<'info, Wallet>,

    #[account(
        init,
        payer = requester,
        space = 8 + SigningRequest::INIT_SPACE,
        seeds = [
            REQUEST_SEED,
            requester.key().as_ref(),
            client_nonce.to_le_bytes().as_ref()
        ],
        bump
    )]
    pub request: Account<'info, SigningRequest>,

    pub system_program: Program<'info, System>,
}

/// Accounts for `activate_wallet` — the caller registers their OWN identity.
/// The wallet PDA is derived from (and stored with) the signer's key, so the
/// account layer alone guarantees a user can only activate their own wallet.
#[derive(Accounts)]
pub struct ActivateWallet<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        init,
        payer = authority,
        space = 8 + Wallet::INIT_SPACE,
        seeds = [WALLET_SEED, protocol.key().as_ref(), authority.key().as_ref()],
        bump
    )]
    pub wallet: Account<'info, Wallet>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(authority: Pubkey)]
pub struct RegisterWallet<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = admin @ DistinError::Unauthorized
    )]
    pub protocol: Account<'info, Protocol>,

    #[account(
        init,
        payer = admin,
        space = 8 + Wallet::INIT_SPACE,
        seeds = [WALLET_SEED, protocol.key().as_ref(), authority.as_ref()],
        bump
    )]
    pub wallet: Account<'info, Wallet>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeWallet<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [PROTOCOL_SEED],
        bump = protocol.bump,
        has_one = admin @ DistinError::Unauthorized
    )]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = protocol @ DistinError::Unauthorized,
        seeds = [WALLET_SEED, protocol.key().as_ref(), wallet.authority.as_ref()],
        bump = wallet.bump,
        close = admin
    )]
    pub wallet: Account<'info, Wallet>,
}

#[derive(Accounts)]
pub struct SubmitPartial<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = protocol @ DistinError::Unauthorized
    )]
    pub request: Account<'info, SigningRequest>,

    #[account(
        mut,
        has_one = authority @ DistinError::Unauthorized,
        has_one = protocol @ DistinError::Unauthorized,
        seeds = [OPERATOR_SEED, protocol.key().as_ref(), authority.key().as_ref()],
        bump = operator.bump
    )]
    pub operator: Account<'info, Operator>,

    #[account(
        init,
        payer = authority,
        space = 8 + PartialSignature::INIT_SPACE,
        seeds = [PARTIAL_SEED, request.key().as_ref(), operator.key().as_ref()],
        bump
    )]
    pub partial: Account<'info, PartialSignature>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AggregateAndEmit<'info> {
    pub relayer: Signer<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = protocol @ DistinError::Unauthorized
    )]
    pub request: Account<'info, SigningRequest>,
}

/// Accounts for `cancel_request` — the requester closes their own request and
/// receives the rent refund. `has_one = requester` ties the signer to the
/// account's owner, so no other party can trigger the close.
#[derive(Accounts)]
pub struct CancelRequest<'info> {
    #[account(mut)]
    pub requester: Signer<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = protocol @ DistinError::Unauthorized,
        has_one = requester @ DistinError::Unauthorized,
        close = requester
    )]
    pub request: Account<'info, SigningRequest>,
}

/// Accounts for `expire_request` — permissionless garbage collection. Any
/// signer may pay to close an *expired* request, but the rent is always
/// refunded to the original requester (`close = requester`), so the caller
/// gains nothing and cannot redirect funds.
#[derive(Accounts)]
pub struct CloseRequest<'info> {
    /// CHECK: rent-refund destination only; identity enforced via `has_one`.
    #[account(mut, address = request.requester @ DistinError::Unauthorized)]
    pub requester: UncheckedAccount<'info>,

    pub closer: Signer<'info>,

    #[account(seeds = [PROTOCOL_SEED], bump = protocol.bump)]
    pub protocol: Account<'info, Protocol>,

    #[account(
        mut,
        has_one = protocol @ DistinError::Unauthorized,
        has_one = requester @ DistinError::Unauthorized,
        close = requester
    )]
    pub request: Account<'info, SigningRequest>,
}

#[event]
pub struct OperatorRegistered {
    pub operator: Pubkey,
    pub authority: Pubkey,
    pub stake_weight: u64,
}

#[event]
pub struct OperatorSlashed {
    pub operator: Pubkey,
    pub amount: u64,
    pub reason: u8,
}

#[event]
pub struct WalletRegistered {
    pub wallet: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct WalletRevoked {
    pub wallet: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct SigningRequestCreated {
    pub request: Pubkey,
    pub request_id: u64,
    pub scheme: SignatureScheme,
    pub target_vm: TargetVm,
    pub target_chain_id: u64,
}

#[event]
pub struct PartialSignatureSubmitted {
    pub request: Pubkey,
    pub operator: Pubkey,
    pub partials_collected: u16,
    pub stake_weight_collected: u64,
}

#[event]
pub struct AggregateSignatureEmitted {
    pub request: Pubkey,
    pub request_id: u64,
    pub scheme: SignatureScheme,
    pub target_vm: TargetVm,
    pub target_chain_id: u64,
    pub message_hash: [u8; 32],
    pub aggregate_sig: [u8; 64],
}

#[cfg(test)]
mod tests {
    //! Unit coverage for the security-critical pure logic: per-scheme partial
    //! share validation and the economic-threshold math. These hold the
    //! invariants an off-chain caller cannot be trusted to enforce, so each
    //! happy path, every rejection path, and the saturation/overflow edges are
    //! exercised here. The Anchor account-constraint layer (signer/PDA/owner
    //! checks) is verified at the integration tier against the deployed program.

    use super::*;

    /// Extract the on-chain error code from a failed `Result`. Anchor assigns
    /// each `DistinError` variant a stable code (`6000 + ordinal`), so an exact
    /// `assert_eq!` against `u32::from(DistinError::X)` pins the precise revert
    /// reason a caller would see — not just "it failed".
    fn code<T: std::fmt::Debug>(r: Result<T>) -> u32 {
        match r.unwrap_err() {
            anchor_lang::error::Error::AnchorError(e) => e.error_code_number,
            other => panic!("expected AnchorError, got {other:?}"),
        }
    }

    fn nonzero_share() -> [u8; 64] {
        let mut s = [0u8; 64];
        s[0] = 1; // first half non-zero
        s[63] = 1; // second half non-zero
        s
    }

    fn nonzero_msg() -> [u8; 32] {
        let mut m = [0u8; 32];
        m[7] = 9;
        m
    }

    #[test]
    fn frost_share_accepts_when_nonce_half_set() {
        let mut share = [0u8; 64];
        share[5] = 1; // nonce-commitment half (bytes 0..32) non-zero
        assert!(
            verify_partial_share(SignatureScheme::FrostEd25519, &share, &nonzero_msg()).is_ok()
        );
    }

    #[test]
    fn frost_share_rejects_when_only_response_half_set() {
        // FROST requires the nonce-commitment half (0..32) to be present.
        let mut share = [0u8; 64];
        share[40] = 1; // only the response half is set
        assert_eq!(
            code(verify_partial_share(
                SignatureScheme::FrostEd25519,
                &share,
                &nonzero_msg()
            )),
            u32::from(DistinError::MalformedPartialSignature)
        );
    }

    #[test]
    fn gg20_share_accepts_when_s_half_set() {
        let mut share = [0u8; 64];
        share[40] = 1; // s-component half (bytes 32..64) non-zero
        assert!(
            verify_partial_share(SignatureScheme::Gg20Secp256k1, &share, &nonzero_msg()).is_ok()
        );
    }

    #[test]
    fn gg20_share_rejects_when_only_r_half_set() {
        // GG20 requires the s half (32..64) to be present.
        let mut share = [0u8; 64];
        share[5] = 1; // only the r half is set
        assert_eq!(
            code(verify_partial_share(
                SignatureScheme::Gg20Secp256k1,
                &share,
                &nonzero_msg()
            )),
            u32::from(DistinError::MalformedPartialSignature)
        );
    }

    #[test]
    fn all_zero_share_rejected_for_both_schemes() {
        let zero = [0u8; 64];
        for scheme in [
            SignatureScheme::FrostEd25519,
            SignatureScheme::Gg20Secp256k1,
        ] {
            assert_eq!(
                code(verify_partial_share(scheme, &zero, &nonzero_msg())),
                u32::from(DistinError::MalformedPartialSignature)
            );
        }
    }

    #[test]
    fn empty_message_hash_rejected() {
        let zero_msg = [0u8; 32];
        assert_eq!(
            code(verify_partial_share(
                SignatureScheme::FrostEd25519,
                &nonzero_share(),
                &zero_msg
            )),
            u32::from(DistinError::EmptyMessageHash)
        );
    }

    #[test]
    fn required_weight_floors_the_product() {
        // 1_000 * 6_667 / 10_000 = 666.7 -> floors to 666.
        assert_eq!(required_stake_weight(1_000, 6_667).unwrap(), 666);
    }

    #[test]
    fn required_weight_full_threshold_is_total() {
        assert_eq!(required_stake_weight(12_345, 10_000).unwrap(), 12_345);
    }

    #[test]
    fn required_weight_min_threshold_floors_to_zero_on_tiny_stake() {
        // 1 * 1 / 10_000 = 0: a single-unit bond at 1bps rounds to no target,
        // which is why finalization *also* gates on `partials_collected`.
        assert_eq!(required_stake_weight(1, 1).unwrap(), 0);
    }

    #[test]
    fn required_weight_overflows_on_saturated_stake() {
        // total_bonded near u64::MAX times any bps > 1 cannot fit in u64.
        assert_eq!(
            code(required_stake_weight(u64::MAX, 10_000)),
            u32::from(DistinError::MathOverflow)
        );
    }

    #[test]
    fn required_weight_zero_stake_is_zero() {
        assert_eq!(required_stake_weight(0, 10_000).unwrap(), 0);
    }
}
