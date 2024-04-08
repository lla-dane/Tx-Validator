
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
    pub prevout: Prevout, // Optional to accommodate transactions without this field
    pub scriptsig: Option<String>,
    pub scriptsig_asm: Option<String>,
    pub witness: Option<Vec<String>>, // Optional to accommodate Non-Segwit transactions
    pub is_coinbase: bool,
    pub sequence: u32,
    pub inner_redeemscript_asm: Option<String>, // Optional for transactions that might not have it
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

// pub fn load_mempool_transactions() -> Result<(Vec<Transaction>)> {
//     let mempool_dir = "./mempool";
//     let mut txs = Vec::new();

//     for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
//         let path = entry.path();
//         if path.is_file() {
//             // Read the file contents into a string.
//             match fs::read_to_string(path) {
//                 Ok(contents) => {
//                     match serde_json::from_str::<Transaction>(&contents) {
//                         Ok(transaction) => {
//                             txs.push(transaction);
//                         }
//                         Err(e) => {
//                             // eprintln!("Failed to parse JSON: {}", e);
//                         }
//                     }
//                 }
//                 Err(e) => {}
//             }
//         }
//     }

//     Ok(txs)
// }
