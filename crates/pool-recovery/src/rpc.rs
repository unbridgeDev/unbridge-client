//! Minimal Solana JSON-RPC client used by the recovery scanner.
//!
//! Deliberately narrow: only the endpoints the recovery flow needs
//! (`getSignaturesForAddress`, `getTransaction`). Ureq for blocking HTTP so
//! the crate stays independent of a runtime. If an integrator already carries
//! `solana_client::rpc_client::RpcClient` in their dep tree, they can pipe
//! the same signature/transaction records into `scan::recover_vault` without
//! going through this client.

use serde::Deserialize;

use crate::errors::RecoveryError;

pub const DEFAULT_MAINNET_RPC: &str = "https://api.mainnet-beta.solana.com";
pub const DEFAULT_DEVNET_RPC: &str = "https://api.devnet.solana.com";

pub struct RpcClient {
    endpoint: String,
    http_timeout_secs: u64,
}

impl RpcClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            http_timeout_secs: 30,
        }
    }

    pub fn mainnet() -> Self {
        Self::new(DEFAULT_MAINNET_RPC)
    }

    pub fn devnet() -> Self {
        Self::new(DEFAULT_DEVNET_RPC)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Fetch a page of signatures that touched `address`, most recent first.
    /// Pass `before` from the last page's tail to paginate deeper.
    pub fn get_signatures_for_address(
        &self,
        address: &str,
        limit: u32,
        before: Option<&str>,
    ) -> Result<Vec<SignatureRecord>, RecoveryError> {
        let mut cfg = serde_json::Map::new();
        cfg.insert("limit".to_string(), serde_json::json!(limit));
        if let Some(b) = before {
            cfg.insert("before".to_string(), serde_json::json!(b));
        }
        let resp: SigResp = self.call("getSignaturesForAddress", serde_json::json!([address, cfg]))?;
        Ok(resp.result.unwrap_or_default())
    }

    /// Fetch a single confirmed transaction with json-parsed encoding so
    /// program logs are already broken into lines.
    pub fn get_transaction(&self, signature: &str) -> Result<Option<TransactionRecord>, RecoveryError> {
        let cfg = serde_json::json!({
            "encoding": "jsonParsed",
            "maxSupportedTransactionVersion": 0,
        });
        let resp: TxResp = self.call("getTransaction", serde_json::json!([signature, cfg]))?;
        Ok(resp.result)
    }

    fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, RecoveryError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let raw: serde_json::Value = ureq::post(&self.endpoint)
            .timeout(std::time::Duration::from_secs(self.http_timeout_secs))
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| RecoveryError::Transport(e.to_string()))?
            .into_json()
            .map_err(|e| RecoveryError::Transport(e.to_string()))?;

        if let Some(err) = raw.get("error") {
            return Err(RecoveryError::RpcError(err.to_string()));
        }
        serde_json::from_value(raw).map_err(|e| RecoveryError::Serialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureRecord {
    pub signature: String,
    #[serde(default)]
    pub slot: u64,
    #[serde(default, rename = "blockTime")]
    pub block_time: Option<i64>,
    #[serde(default)]
    pub err: Option<serde_json::Value>,
}

impl SignatureRecord {
    /// True iff the transaction landed without error.
    pub fn is_success(&self) -> bool {
        self.err.is_none()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionRecord {
    #[serde(default)]
    pub slot: u64,
    #[serde(default, rename = "blockTime")]
    pub block_time: Option<i64>,
    pub meta: Option<TxMeta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TxMeta {
    #[serde(default, rename = "logMessages")]
    pub log_messages: Option<Vec<String>>,
    #[serde(default)]
    pub err: Option<serde_json::Value>,
}

impl TransactionRecord {
    pub fn logs(&self) -> &[String] {
        self.meta
            .as_ref()
            .and_then(|m| m.log_messages.as_deref())
            .unwrap_or_default()
    }

    pub fn is_success(&self) -> bool {
        self.meta
            .as_ref()
            .map(|m| m.err.is_none())
            .unwrap_or(false)
    }
}

#[derive(Deserialize)]
struct SigResp {
    result: Option<Vec<SignatureRecord>>,
}

#[derive(Deserialize)]
struct TxResp {
    result: Option<TransactionRecord>,
}
