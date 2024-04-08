use hex;
use log::info;

use crate::transaction::{self, Input, Output, Prevout};
use crate::validation_checks::double_sha256;
use crate::validation_checks::hash160;
use crate::validation_checks::op_checkmultisig;
use crate::validation_checks::op_checksig;

use crate::{error::Result, transaction::Transaction};

pub fn input_verification_p2wpkh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    Ok(script_execution_p2wpkh(witness, tx, tx_input_index)?)
}

fn script_execution_p2wpkh(
    witness: Vec<String>,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    if witness.len() == 0 {
        return Ok(false);
    }

    if tx.vin[tx_input_index].scriptsig.clone().unwrap().len() != 0 {
        return Ok(false);
    } 

    let input_type = "P2WPKH";

    let mut stack = Vec::new();

    // PUSHING COMPONENTS OF THE WITNESS IN THE STACK := SIGNATURE AND PUBLIC KEY
    stack.push(hex::decode(&witness[0])?);
    stack.push(hex::decode(&witness[1])?);

    // OP_CHECKSIG
    let script_result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

    Ok(script_result)
}

#[cfg(test)]
mod test {
    use std::fs;

    use walkdir::WalkDir;

    use super::*;

    #[test]
    fn test_script_execution_p2wpkh() -> Result<()> {
        let mut s_count = 0;
        let mut f_count = 0;
        let mempool_dir = "./mempool";
        for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                match fs::read_to_string(path) {
                    Ok(contents) => {
                        match serde_json::from_str::<Transaction>(&contents) {
                            Ok(transaction) => {
                                // Check if all inputs' prevout scriptpubkey_type are .p2sh
                                let all_p2sh = transaction.vin.iter().all(|input| {
                                    input.prevout.scriptpubkey_type == "v0_p2wpkh".to_string()
                                });
                                if all_p2sh {
                                    let result = script_execution_p2wpkh(
                                        transaction.vin[0].witness.clone().unwrap(),
                                        transaction,
                                        0,
                                    )?;

                                    if result == true {
                                        s_count += 1;
                                    } else {
                                        f_count += 1;
                                    }

                                    println!("\n\n");
                                }
                            }
                            Err(e) => {
                                println!("Failed to parse JSON: {}", e);
                            }
                        }
                    }
                    Err(e) => eprintln!("Failed to read file: {}", e),
                }
            }
        }

        println!("success: {}", s_count);
        println!("failure: {}", f_count);

        Ok(())
    }
}

//         let dummy_tx = Transaction {
//         version: 2,
//     locktime: 832833,
//     vin: vec![
//         Input {
//             txid: "a0ec1b6f62ad5b175ead2f6f5936864670268bda3dc75219964651f6992c3b30".to_string(),
//             vout: 0,
//             prevout: Prevout {
//                 scriptpubkey: "0014bbc929d578282030410cfaf2136be62fea7b7a77".to_string(),
//                 scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 bbc929d578282030410cfaf2136be62fea7b7a77".to_string(),
//                 scriptpubkey_type: "v0_p2wpkh".to_string(),
//                 scriptpubkey_address: "bc1qh0yjn4tc9qsrqsgvltepx6lx9l48k7nhccjsje".to_string(),
//                 value: 19977,
//             },
//             scriptsig: Some(
//                 "".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "".to_string(),
//             ),
//             witness: Some( vec!
//                 [
//                     "3044022036ba7933c3fffa7020081f788bc22cda91d654f018625dcd7c69687adb4d411502203d73c9c1cd13e33d07b9a321e1988ffa945fbc076962a35c98b9f432c16a24d901".to_string(),
//                     "020063bfaa615d5b1a5a69f6d3fd2ff1559863270ccf623986fd348aa1cd912d48".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: None,
//         },
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "001482de54f8dee73234dc297c4f7a3334981b69f436".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 82de54f8dee73234dc297c4f7a3334981b69f436".to_string(),
//             scriptpubkey_type: "v0_p2wpkh".to_string(),
//             scriptpubkey_address: Some(
//                 "bc1qst09f7x7uuerfhpf038h5ve5nqdknapk5f7fwg".to_string(),
//             ),
//             value: 19015,
//         },
//     ],
// };
