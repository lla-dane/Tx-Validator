
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<Input>,
    pub vout: Vec<Output>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub txid: String,
    pub vout: u32,
    pub prevout: Prevout, 
    pub scriptsig: Option<String>,
    pub scriptsig_asm: Option<String>,
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
    pub inner_redeemscript_asm: Option<String>, 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Prevout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Output {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}
