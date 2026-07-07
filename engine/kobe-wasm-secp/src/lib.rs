// Spike: can the audited frost-secp256k1 (ZF) run a 2-of-2 in wasm and produce a
// Schnorr signature? This is the load-bearing question for browser-side Bitcoin
// Taproot custody. Answer first; BIP340 compatibility is the next question.
use frost_secp256k1_tr as frost;
use std::collections::BTreeMap;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use frost::{keys::KeyPackage, round1, round2, Identifier, Signature, SigningPackage, VerifyingKey};

#[wasm_bindgen]
pub fn secp_selftest(message_hex: &str) -> String {
    match run(message_hex) { Ok(j) => j, Err(e) => format!("{{\"ok\":false,\"error\":\"{}\"}}", e.replace('"',"'")) }
}
fn run(message_hex: &str) -> Result<String, String> {
    let message = hex::decode(message_hex).map_err(|e| e.to_string())?;
    let (shares, pkg) = frost::keys::generate_with_dealer(2,2,frost::keys::IdentifierList::Default,OsRng).map_err(|e| e.to_string())?;
    let mut kps: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (i,s) in shares { kps.insert(i, KeyPackage::try_from(s).map_err(|e| e.to_string())?); }
    let ids: Vec<Identifier> = vec![Identifier::try_from(1u16).unwrap(), Identifier::try_from(2u16).unwrap()];
    let mut nonces = BTreeMap::new(); let mut commits = BTreeMap::new();
    for i in &ids { let (n,c) = round1::commit(kps[i].signing_share(), &mut OsRng); nonces.insert(*i,n); commits.insert(*i,c); }
    let sp = SigningPackage::new(commits, &message);
    let mut sigs = BTreeMap::new();
    for i in &ids { sigs.insert(*i, round2::sign(&sp,&nonces[i],&kps[i]).map_err(|e| e.to_string())?); }
    let group_sig: Signature = frost::aggregate(&sp,&sigs,&pkg).map_err(|e| e.to_string())?;
    let gpk = pkg.verifying_key().serialize().map_err(|e| e.to_string())?;
    let sig = group_sig.serialize().map_err(|e| e.to_string())?;
    let vk = VerifyingKey::deserialize(&gpk).map_err(|e| e.to_string())?;
    let verified = vk.verify(&message, &group_sig).is_ok();
    Ok(format!("{{\"ok\":true,\"group_pubkey\":\"{}\",\"group_pubkey_len\":{},\"signature\":\"{}\",\"sig_len\":{},\"verified\":{}}}",
        hex::encode(&gpk), gpk.len(), hex::encode(&sig), sig.len(), verified))
}
