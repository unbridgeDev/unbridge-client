use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("RPC transport error: {0}")]
    Transport(String),

    #[error("RPC returned error: {0}")]
    RpcError(String),

    #[error("could not decode base64 payload: {0}")]
    Base64(String),

    #[error("could not parse program log line: {0}")]
    LogParse(String),

    #[error("nullifier byte string was {got} bytes, expected 32")]
    BadNullifierLength { got: usize },

    #[error("underlying pool-note error: {0}")]
    Note(#[from] pool_note::NoteError),

    #[error("serialization error: {0}")]
    Serialization(String),
}
