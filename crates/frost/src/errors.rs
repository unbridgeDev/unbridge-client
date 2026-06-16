use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrostError {
    #[error("participant identifier must be non-zero")]
    ZeroParticipantId,

    #[error("threshold {t} exceeds participant count {n}")]
    ThresholdTooHigh { t: u16, n: u16 },

    #[error("threshold {t} must be at least 2 for a group signature")]
    ThresholdTooLow { t: u16 },

    #[error("duplicate participant id {0}")]
    DuplicateParticipant(u16),

    #[error("signer {0} not part of the current signing set")]
    UnknownSigner(u16),

    #[error("insufficient signers: got {got}, need {need}")]
    InsufficientSigners { got: usize, need: usize },

    #[error("invalid share from participant {0}: verification commitment mismatch")]
    InvalidShare(u16),

    #[error("invalid partial signature from participant {0}")]
    InvalidPartial(u16),

    #[error("aggregated signature failed verification against the group key")]
    AggregatedVerifyFailed,

    #[error("nonce reused: fresh nonce required for each session")]
    NonceReused,

    #[error("Poseidon hash failed")]
    PoseidonHashFailed,

    #[error("serialization failed: {0}")]
    Serialization(String),
}
