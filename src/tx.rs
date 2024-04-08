use crate::{error::Result, transaction};
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, fs};
use walkdir::WalkDir;

// Define a structure that matches the JSON structure of your transactions.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    version: i32,
    locktime: u64,
    vin: Vec<Input>,
    vout: Vec<Output>,
}

// The type of transactions in terms of SEGWIT and NON-SEGWIT, is determined by how inputs are structured, in regard of spending of
// previous outputs and the inclusion of witness data.
// A transaction is identified as SegWit primarily based on the presence of witness data for its inputs.

// Non-Segwit Transactions: must have [`PrevOut`] to understand the output being spent and [`scriptsig`] for authorisation.
// Segwit Transactions: Must have [`PrevOut`] for context of output being spent and [`witness`] for data proving authorisation to spend.

// Differenetiate between Segwit and Non-Segwit Transactions
// Non-SegWit script types: p2pkh, p2sh
// SegWit script types: v0_wpkh, v0_wsh, v1_p2tr

// NON-SEGWIT: script-sig includes the signature and public key of the spender for p2pkh and p2sh
// SEGWIT: witness contains the signature and public key of the spender for p2wpkh, p2tr, p2wsh

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Input {
    txid: String,
    vout: u32,
    prevout: PrevOut,
    scriptsig: Option<String>,
    scriptsig_asm: Option<String>,
    witness: Option<Vec<String>>,
    is_coinbase: bool,
    sequence: u64,
    inner_redeemscript_asm: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PrevOut {
    // Represenst the output being spent by the input
    scriptpubkey: String, // Script is executed during validation to verify that the spender has the required credentials
    scriptpubkey_asm: String, // Assembly representation of the script pub key
    scriptpubkey_type: String, // Non-SegWit[p2pkh, p2sh], Segwit[v0_wpkh, v0_wsh, v1_p2tr]
    scriptpubkey_address: String, // Address derived form [`scriptpubkey`] to specify where the bitcoins are sent to
    value: u64,                   // Number of sats in the input
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Output {
    scriptpubkey: String, // Locking script that specifies the condition under which the output can be spent
    scriptpubkey_asm: String,
    scriptpubkey_type: String, // Indicates the type of script encoded in scriptpubkey
    scriptpubkey_address: Option<String>, // Address derived from the scriptpubkey, the recepient address
    value: u64,
}
pub fn load_transactions() -> Result<()> {
    let mempool_dir = "./mempool";
    let mut invalid_tx = Vec::new();

    for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            // Read the file contents into a string.
            match fs::read_to_string(path) {
                Ok(contents) => {
                    // Parse the JSON string into the Transaction struct.
                    match serde_json::from_str::<Transaction>(&contents) {
                        Ok(transaction) => {
                            // Check if all inputs' prevout scriptpubkey_type are .p2sh
                            let all_p2sh = transaction.vin.iter().all(|input| {
                                input.prevout.scriptpubkey_type == "v1_p2tr"
                            });
                            if all_p2sh {
                                println!("{:#?}\n", transaction);
                                println!("{}\n", path.display().to_string());
                                // for input in transaction.vin.iter() {
                                //     println!("{:#?}\n", input.prevout.scriptpubkey_asm.clone());
                                //     println!("{:#?}", input.witness.clone().unwrap());
                                //     break;
                                // }
                                // println!("-------------------------------------\n");
                            } else {
                                // If any input is not p2sh, you could decide to add it to a different vector
                                // For this example, we just ignore the transaction
                            }
                        }
                        Err(e) => {
                            println!("Failed to parse JSON: {}", e);
                            invalid_tx.push(path.display().to_string());
                        }
                    }
                }
                Err(e) => eprintln!("Failed to read file: {}", e),
            }
        }
    }
    Ok(())
}


// <= fffffffe - 4294967294 locktime
//    fffffffd - 4294967293 replace by fee
//    efffffff - 4026531839 relative locktime