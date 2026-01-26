//! Custom error codes for the Distin threshold-signature coordination layer.

use anchor_lang::prelude::*;

#[error_code]
pub enum DistinError {
    #[msg("Protocol is paused")]
    ProtocolPaused,

    #[msg("Caller is not authorized for this action")]
    Unauthorized,

    #[msg("Threshold must be between 1 and the active operator count / 10000 bps")]
    InvalidThreshold,

    #[msg("Bond amount is below the configured minimum")]
    InsufficientBond,

    #[msg("Operator is jailed or unbonding and cannot sign")]
    OperatorJailed,

    #[msg("Operator is already unbonding")]
    AlreadyUnbonding,

    #[msg("Operator has not begun unbonding")]
    NotUnbonding,

    #[msg("Unbonding period has not elapsed yet")]
    UnbondingNotComplete,

    #[msg("Signing request has expired")]
    RequestExpired,

    #[msg("Signing request is not in a pending state")]
    RequestNotPending,

    #[msg("Collected staked weight or partial count is below threshold")]
    ThresholdNotMet,

    #[msg("Signing request has already been finalized")]
    RequestAlreadyFinalized,

    #[msg("Partial signature share is malformed")]
    MalformedPartialSignature,

    #[msg("Message hash must be non-empty")]
    EmptyMessageHash,

    #[msg("Oracle price is stale")]
    StaleOraclePrice,

    #[msg("Oracle account does not match the configured price feed")]
    InvalidOracleAccount,

    #[msg("Provided vault or pool account is invalid")]
    InvalidVault,

    #[msg("Validity window is outside the allowed bounds")]
    InvalidValidityWindow,

    #[msg("No active operators in the signing set")]
    NoActiveOperators,

    #[msg("Slash amount exceeds the operator's bonded collateral")]
    SlashAmountExceedsBond,

    #[msg("Invalid admin transfer target")]
    InvalidAdminTransfer,

    #[msg("Arithmetic overflow")]
    MathOverflow,
}
