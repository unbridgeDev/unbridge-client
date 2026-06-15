use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NoteError {
    #[error("amount {0} lamports is not one of the ten pool denominations")]
    NonStandardDenomination(u64),

    #[error("field element out of range for BN254 scalar")]
    FieldOutOfRange,

    #[error("Poseidon hash failed")]
    PoseidonHashFailed,

    #[error("ciphertext failed authentication under the view key")]
    DecryptAuthFailed,

    #[error("ciphertext too short: got {got}, need at least {need}")]
    CiphertextTooShort { got: usize, need: usize },
}
