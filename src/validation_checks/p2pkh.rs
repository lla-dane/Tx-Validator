// Here we will operaeton the p2pkh transactions
use hex;
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::transaction::Transaction;

pub fn input_verification_p2pkh(tx: Transaction, tx_input_index: usize) -> Result<bool> {
    // get signature and public key from the scriptsig_asm

    let scriptsig_asm = match tx.vin[tx_input_index].scriptsig_asm.clone() {
        Some(value) => value,
        None => {
            // println!("scriptsig_asm missing...!!");
            return Ok(false);
        }
    };

    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();

    Ok(script_execution(
        scriptpubkey_asm,
        scriptsig_asm,
        tx,
        tx_input_index,
    ))
}

fn script_execution(
    scriptpubkey_asm: String,
    scriptsig_asm: String,
    tx: Transaction,
    tx_input_index: usize,
) -> bool {
    let sigscript_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();

    let signature = *sigscript_asm_slices.get(1).expect("Signature missing");
    let pubkey = *sigscript_asm_slices.get(3).expect("Public key missing");

    let sig = hex::decode(signature).expect("Failed to decode signature");
    let pubkey = hex::decode(pubkey).expect("Failed to decode public key");

    let mut stack: Vec<Vec<u8>> = Vec::new();

    stack.push(sig);
    stack.push(pubkey);

    let op_codes: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();

    for op_code in op_codes.iter() {
        match *op_code {
            "OP_DUP" => {
                let top = stack.last().cloned().expect("STACK UNDEFLOW: OP_DUP");
                stack.push(top);
            }
            "OP_HASH160" => {
                let top = stack.pop().expect("STACK UNDERFLOW: OP_HASH160");
                let hash = hash160(&top);
                stack.push(hash);
            }
            "OP_PUSHBYTES_20" => {
                // The next iteration will have the actual bytes to push
                continue;
            }
            _ => {
                // Assuming the curernt op_code is the bytes pushed by OP_PUSHBYTES_20
                if op_code.len() == 40 {
                    stack.push(hex::decode(op_code).unwrap());
                } else if *op_code == "OP_EQUALVERIFY" {
                    let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");
                    let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");

                    if a != b {
                        // println!("OP_EQUALVERIFY: FAILED");
                        return false;
                    }
                } else if *op_code == "OP_CHECKSIG" {
                    // ASSUMING SIG IS CORRECT
                    let result = op_checksig(&tx, tx_input_index);

                    if result == true {
                        continue;
                    } else {
                        // println!("OP_CHECKSIG: FAILED");
                        return false;
                    }
                }
            }
        }
    }
    // println!("SCRIPT EXECUTION: SUCCESSFULL");
    true
}

fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(data)).to_vec()
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

fn op_checksig(tx: &Transaction, tx_input_index: usize) -> bool {
    let mut trimmed_tx = Vec::new();

    trimmed_tx.extend(&tx.version.to_le_bytes());
    trimmed_tx.push(tx.vin.len() as u8);

    for input_index in 0..tx.vin.len() {
        let mut txid_bytes_reversed =
            hex::decode(&tx.vin[input_index].txid).expect("DECODING FAILED");

        txid_bytes_reversed.reverse();

        trimmed_tx.extend_from_slice(&txid_bytes_reversed);
        trimmed_tx.extend(&tx.vin[input_index].vout.to_le_bytes());

        if input_index == tx_input_index {
            let script_pub_key_bytes =
                hex::decode(&tx.vin[input_index].prevout.scriptpubkey).expect("DECODING FAILED");
            trimmed_tx.push(script_pub_key_bytes.len().try_into().unwrap());
            trimmed_tx.extend_from_slice(&script_pub_key_bytes);
        } else {
            trimmed_tx.push(0 as u8);
        }

        trimmed_tx.extend(&tx.vin[input_index].sequence.to_le_bytes());
    }

    trimmed_tx.push(tx.vout.len() as u8);

    for tx_ouput in tx.vout.iter() {
        let script_pub_key_bytes =
            hex::decode(tx_ouput.scriptpubkey.clone()).expect("DECODING FAILED");

        trimmed_tx.extend(tx_ouput.value.to_le_bytes());
        trimmed_tx.push(script_pub_key_bytes.len().try_into().unwrap());
        trimmed_tx.extend_from_slice(&script_pub_key_bytes);
    }

    trimmed_tx.extend(&tx.locktime.to_le_bytes());

    if let Some(sighash_type) = extract_sighash_type(
        tx.vin[tx_input_index]
            .scriptsig_asm
            .clone()
            .expect("SCRIPT SIG ASM: MISSING"),
    ) {
        trimmed_tx.extend(&sighash_type.to_le_bytes());
    }

    // THE TRIMMED TRANSACTION IS READY

    let scriptsig_asm = tx.vin[tx_input_index]
        .scriptsig_asm
        .clone()
        .expect("SCRIPT SIG ASM: MISSING");
    let scriptsig_asm_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();

    let signature = scriptsig_asm_slices[1];
    let pubkey = scriptsig_asm_slices[3];

    // println!("{}", hex::encode(trimmed_tx.clone()));

    // println!("{}", hex::encode(trimmed_tx.clone()));

    let trimmed_tx_hash = double_sha256(&trimmed_tx);
    let signature_bytes = hex::decode(signature).expect("DECODING: FAILED");
    let pubkey_bytes = hex::decode(pubkey).expect("DECODING: FAILED");

    let secp = Secp256k1::new();
    let public_key = PublicKey::from_slice(&pubkey_bytes).expect("ERROR PARSING: PUBLIC KEY");
    let signature = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1]).unwrap();

    let message =
        Message::from_digest_slice(&trimmed_tx_hash).expect("ERROR CREATING MESSAGE FROM TX_HASH");

    // println!("{}", message);
    // println!("{}", signature);

    match secp.verify_ecdsa(&message, &signature, &public_key) {
        Ok(_) => {
            println!("SIGNATURE: VALID");
            return true;
        }
        Err(_) => return false,
    }
}

fn extract_sighash_type(scriptsig_asm: String) -> Option<u32> {
    let scriptsig_slices: Vec<&str> = scriptsig_asm.split_whitespace().collect();
    let signature = scriptsig_slices[1];
    let sig_bytes = hex::decode(signature).ok()?;
    let sighash_type = sig_bytes.last().copied().expect("NOT FOUND") as u32;

    Some(sighash_type)
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use walkdir::WalkDir;

    #[test]
    fn test_script_execution_p2pkh() -> Result<()> {
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
                                let all_p2sh = transaction.clone().vin.iter().all(|input| {
                                    input.prevout.scriptpubkey_type == "p2pkh".to_string()
                                });

                                let mut tx_result = true;

                                if all_p2sh {
                                    for input_index in 0..transaction.vin.len() {
                                        let scriptsig_asm = transaction.clone().vin[input_index]
                                            .scriptsig_asm
                                            .clone()
                                            .expect("ASM: MISSING");

                                        let tx = transaction.clone();
                                        let result = script_execution(
                                            tx.vin[input_index].prevout.scriptpubkey_asm.clone(),
                                            scriptsig_asm,
                                            tx,
                                            input_index,
                                        );
                                        if result == false {
                                            tx_result = false;
                                            break;
                                        }
                                    }

                                    if tx_result == true {
                                        s_count += 1;
                                    } else {
                                        f_count += 1;
                                    }

                                    // println!("\n\n");
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

    #[test]
    fn test2() -> Result<()> {
        let path =
            "./mempool/01f16e8312f9c882e869d31a3ab386b94a38f6091f7e947c6f2ed2b3389f4406.json";

        // Read the JSON file
        let data = fs::read_to_string(path).expect("Unable to read file");

        // Deserialize JSON into Rust data structures
        let transaction: Transaction = serde_json::from_str(&data)?;

        let scriptsig_asm = transaction.clone().vin[0]
            .scriptsig_asm
            .clone()
            .expect("ASM: MISSING");

        let tx = transaction.clone();
        let result = script_execution(
            tx.vin[0].prevout.scriptpubkey_asm.clone(),
            scriptsig_asm,
            tx,
            0,
        );

        println!("{}", result);

        Ok(())
    }
}

//         let dummy_tx: Transaction = Transaction {
//     version: 2,
//     locktime: 0,
//     vin: vec![
//         Input {
//             txid: "f7268fdc3dd4ab2ce606a9857f321f9c9d94a7cc4ca7d31db481938ce222403e".to_string(),
//             vout: 28,
//             prevout: Prevout {
//                 scriptpubkey: "76a9145ae0dedcb9a96b8d4310e4ff137a22e0233258e988ac".to_string(),
//                 scriptpubkey_asm: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 5ae0dedcb9a96b8d4310e4ff137a22e0233258e9 OP_EQUALVERIFY OP_CHECKSIG".to_string(),
//                 scriptpubkey_type: "p2pkh".to_string(),
//                 scriptpubkey_address: "19HXCYbrynpvTMYkQoneBgo3xEnXPFDd4z".to_string(),
//                 value: 150653
//             },
//             scriptsig: Some("483045022100cfa7d65576fafd8f827904a1292b55d234898c1e444cd2dfc05f5e15b6f69e4402200b7ea6a9e3da80ea771fe1170795adcbea88d67eb8d82828e85d4b5883b9f9a80121038e464810ac06e1a7589e58bd9050ff1fc4d4768f00aaeedb2d4b5c231ac8851d".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_72 3045022100cfa7d65576fafd8f827904a1292b55d234898c1e444cd2dfc05f5e15b6f69e4402200b7ea6a9e3da80ea771fe1170795adcbea88d67eb8d82828e85d4b5883b9f9a801 OP_PUSHBYTES_33 038e464810ac06e1a7589e58bd9050ff1fc4d4768f00aaeedb2d4b5c231ac8851d".to_string()),
//             witness: None,
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: None
//         }
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "0014bc2870381de4d706a92105419f0c3072e26532d1".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 bc2870381de4d706a92105419f0c3072e26532d1".to_string(),
//             scriptpubkey_type: "v0_p2wpkh".to_string(),
//             scriptpubkey_address: Some("bc1qhs58qwqauntsd2fpq4qe7rpswt3x2vk3krdvhh".to_string()),
//             value: 147107
//         }
//     ]
// };
