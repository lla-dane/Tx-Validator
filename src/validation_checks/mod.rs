use std::{
    collections::HashMap,
    fs::{self},
    path::Path,
};

use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{error::Result, transaction::Transaction};

use self::{
    p2pkh::input_verification_p2pkh, p2sh::input_verification_p2sh,
    p2wpkh::input_verification_p2wpkh, p2wsh::input_verification_p2wsh,
};

pub mod p2pkh;
pub mod p2sh;
pub mod p2wpkh;
pub mod p2wsh;

pub fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(data)).to_vec()
}

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

pub fn single_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn op_checksig(
    stack: &mut Vec<Vec<u8>>,
    tx: Transaction,
    tx_input_index: usize,
    input_type: &str,
) -> Result<bool> {
    let dummy_pubkey: PublicKey = PublicKey::from_slice(
        &hex::decode("03bf68f1ce783df58a2459d549d5c655a1edc0f0cf4d79421fe978d358d79ee42a").unwrap(),
    )
    .unwrap();

    let dummy_signature: Signature = Signature::from_der(&hex::decode("304402205112f96bf7423703c221976603307f0e33913d39efc3344d68376fd2b8c0bd20022003ea588c06fa1a3e262e07ed6bf01a36f78741fe7bc6a91ff43c38a0a14e43fe").unwrap()).unwrap();

    // POP THE PUBLIC KEY FROM THE STACK

    let pubkey_bytes = stack.pop().unwrap();

    let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap_or(dummy_pubkey);

    let signature_bytes = stack.pop().expect("STACK UNDERFLOW");

    // println!("{:?}", pubkey_bytes);
    // println!("{:?}", signature_bytes);

    let sig = Signature::from_der(&signature_bytes[..signature_bytes.len() - 1])
        .unwrap_or(dummy_signature);

    // EXTRACT THE SIGHASH TYPE
    let sighash_type = signature_bytes.last().copied().expect("SIGHASH: MISSING") as u32;

    let mut trimmed_tx = trimmed_tx(tx.clone(), tx_input_index, input_type, sighash_type.clone())?;
    trimmed_tx.extend(&sighash_type.to_le_bytes());

    // println!("{}", hex::encode(trimmed_tx.clone()));

    let trimmed_tx_hash = double_sha256(&trimmed_tx);

    let msg = Message::from_digest_slice(&trimmed_tx_hash).expect("PARSING: FAILED");

    // VERIFYING THE SIGNATURE
    let secp = Secp256k1::new();

    let mut result: bool = false;

    if secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok() {
        result = true;
        // println!("OP_CHECKSIG: SUCCESSFULL");
    } else {
        // println!("OP_CHECKSIG: FAILED")
    }

    Ok(result)
}

pub fn op_checkmultisig(
    stack: &mut Vec<Vec<u8>>,
    tx: Transaction,
    tx_input_index: usize,
    input_type: &str,
) -> Result<bool> {
    let dummy_pubkey: PublicKey = PublicKey::from_slice(
        &hex::decode("03bf68f1ce783df58a2459d549d5c655a1edc0f0cf4d79421fe978d358d79ee42a").unwrap(),
    )
    .unwrap();

    let dummy_signature: Signature = Signature::from_der(&hex::decode("304402205112f96bf7423703c221976603307f0e33913d39efc3344d68376fd2b8c0bd20022003ea588c06fa1a3e262e07ed6bf01a36f78741fe7bc6a91ff43c38a0a14e43fe").unwrap()).unwrap();

    // POP THE PUBLIC KEYS FROM THE STACK
    let mut n_keys = 0;
    if let Some(item) = stack.pop() {
        if let Some(&byte) = item.first() {
            n_keys = byte as u8;
        }
    }

    let mut pubkeys: Vec<PublicKey> = Vec::new();

    for _ in 0..n_keys {
        let pubkey_bytes = stack.pop().expect("STACK UNDERFLOW: PUBKEY");
        pubkeys.push(PublicKey::from_slice(&pubkey_bytes).unwrap_or(dummy_pubkey));
    }

    // POP THE SIGNATURES FROM THE STACK
    let mut n_signatures = 0;
    if let Some(item) = stack.pop() {
        if let Some(&byte) = item.first() {
            n_signatures = byte as u8;
        }
    }

    let mut signatures: Vec<(Signature, u32)> = Vec::new();

    for _ in 0..n_signatures {
        let signature_bytes = stack.pop().expect("STACK UNDERFLOW: SIGNATURES");

        // EXTRACT THE SIGHASH TYPE
        let sighash_type = signature_bytes.last().copied().expect("SIGHASH: MISSING") as u32;
        signatures.push((
            Signature::from_der(&signature_bytes[..&signature_bytes.len() - 1])
                .unwrap_or(dummy_signature),
            sighash_type,
        ));
    }

    let secp = Secp256k1::new();
    let mut valid_sig_count = 0;

    let mut x: String = String::new();

    for (sig, sighash) in signatures {
        // TRIM THE TRANSACTION AS PER THE SIGHASH_TYPE
        let mut trimmed_tx = trimmed_tx(tx.clone(), tx_input_index, input_type, sighash.clone())?;
        trimmed_tx.extend(&sighash.to_le_bytes());

        x = hex::encode(trimmed_tx.clone());

        let trimmed_tx_hash = double_sha256(&trimmed_tx);
        let msg = Message::from_digest_slice(&trimmed_tx_hash).expect("PARSING: FAILED");

        for pk in &pubkeys {
            if secp.verify_ecdsa(&msg, &sig, pk).is_ok() {
                valid_sig_count += 1;
                break;
            }
        }
    }

    // println!("{}", x);

    let result;

    if valid_sig_count == n_signatures {
        // println!("OP_MULTICHECKSIG: SUCCESSFULL");
        result = true;
    } else {
        // println!("OP_MULTICHECKSIG: FAILED");
        // println!("{}", valid_sig_count);
        result = false;
    }

    Ok(result)
}

pub fn trimmed_tx(
    tx: Transaction,
    tx_input_index: usize,
    input_type: &str,
    sighash_type: u32,
) -> Result<Vec<u8>> {
    let mut trimmed_tx: Vec<u8> = Vec::new();

    if sighash_type == 01 {
        if input_type == "NON_SEGWIT" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            // INPUTS
            trimmed_tx.push(tx.vin.len() as u8);

            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed =
                    hex::decode(&tx.vin[input_index].txid).expect("DECODING: FAILED");
                txid_bytes_reversed.reverse();

                trimmed_tx.extend_from_slice(&txid_bytes_reversed);
                trimmed_tx.extend(&tx.vin[input_index].vout.to_le_bytes());

                // PUSHING THE INPUTS IN THE BYTE SEQUENCE
                if input_index == tx_input_index {
                    // PUSHING THE REDEEM SCRIPT IN PLACE OF SCRIPT PUB KEY
                    let scriptsig_asm = tx.vin[input_index]
                        .scriptsig_asm
                        .clone()
                        .unwrap_or("SCRIPT SIG ASM: MISSING".to_string());

                    let scriptsig_asm_slices: Vec<&str> =
                        scriptsig_asm.split_whitespace().collect();

                    let redeem_script = scriptsig_asm_slices
                        .last()
                        .cloned()
                        .expect("STACK UNDERFLOW");

                    let redeem_script_bytes = hex::decode(redeem_script)?;

                    trimmed_tx.push(redeem_script_bytes.len().try_into()?);
                    trimmed_tx.extend_from_slice(&redeem_script_bytes);
                } else {
                    trimmed_tx.push(0 as u8);
                }
                trimmed_tx.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }

            // OUTPUTS
            trimmed_tx.push(tx.vout.len() as u8);

            // PUSHING THE OUTPUTS IN THE BYTE SEQUENCE
            for tx_ouput in tx.vout.iter() {
                let script_pubkey_bytes =
                    hex::decode(tx_ouput.scriptpubkey.clone()).expect("DECODING FAILED");

                trimmed_tx.extend(tx_ouput.value.to_le_bytes());
                trimmed_tx.push(script_pubkey_bytes.len().try_into()?);
                trimmed_tx.extend_from_slice(&script_pubkey_bytes);
            }
            trimmed_tx.extend(&tx.locktime.to_le_bytes());
        }

        if input_type == "P2SH-P2WPKH" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            // PUSHING HASHPREVOUTS AND HASHSEQUENCE
            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            // OUTPOINTS FOR THE INPUT BEING VERIFIED

            // SUBPARTS :-

            // PUSING THE REVERSED TXID
            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            // EXTRACTING THE REDEEM SCRIPT FROM THE INNER REDEEM SCRIPT ASM
            let inner_redeemscript_asm = tx.vin[tx_input_index]
                .inner_redeemscript_asm
                .clone()
                .unwrap_or("REDEEM SCRIPT: MISSING".to_string());

            let inner_redeemscript_asm_slices: Vec<&str> =
                inner_redeemscript_asm.split_whitespace().collect();
            let redeem_script = inner_redeemscript_asm_slices
                .last()
                .cloned()
                .unwrap_or("REDEEM SCRIPT: MISSING");

            // CREATING AND PUSHING THE SCRIPT CODE
            let scrip_code = format!("{}{}{}", "1976a914", redeem_script, "88ac");
            let script_code_bytes = hex::decode(&scrip_code)?;

            trimmed_tx.extend_from_slice(&script_code_bytes);

            // PUSHING THE AMOUNT
            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            // PUSHING THE SEQUENCE
            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            // PUSHING THE OUTPUTS IN THE SEQUENCE

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            // PUSHING THE LOCKTIME
            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }

        if input_type == "P2SH-P2WSH" {
            trimmed_tx.extend(&tx.version.to_le_bytes());

            // PUSHING HASHPREVOUTS AND HASHSEQUENCE
            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            // OUTPOINTS FOR THE INPUT BEING VERIFIED

            // SUBPARTS :-

            // PUSING THE REVERSED TXID
            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            // SCRIPT CODE

            // EXTRACTING THE REDEEM SCRIPT FROM THE WITNESS
            let witness_script_hex = tx.vin[tx_input_index]
                .witness
                .clone()
                .expect("WITNESS: MISSING")
                .last()
                .cloned()
                .expect("WITNESS SCRIPT: MISSING");

            let script_code_bytes = hex::decode(&witness_script_hex)?;

            trimmed_tx.push(script_code_bytes.len().try_into()?);
            trimmed_tx.extend_from_slice(&script_code_bytes);

            // PUSHING THE AMOUNT
            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            // PUSHING THE SEQUENCE
            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            // PUSHING THE OUTPUTS IN THE SEQUENCE

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            // PUSHING THE LOCKTIME
            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }

        if input_type == "P2WPKH" {
            // println!("P2WPKH");
            trimmed_tx.extend(&tx.version.to_le_bytes());

            // PUSHING HASHPREVOUTS AND HASHSEQUENCE
            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            // OUTPOINTS FOR THE INPUT BEING VERIFIED

            // SUBPARTS :-

            // PUSING THE REVERSED TXID
            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            // SCRIPT CODE

            // EXTRACTING THE PUBLIC KEY HASH FROM THE SCRIPT PUB KEY ASM
            let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();

            let scriptpubkey_slices: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();

            // script-code 0x1976a914{20-byte-pubkey-hash}88ac

            let pubkey_hash = scriptpubkey_slices
                .last()
                .cloned()
                .unwrap_or("SCRIPT PUB KEY: MISSING");
            let script_code_hex = format!("{}{}{}", "1976a914", pubkey_hash, "88ac");

            let script_code_bytes = hex::decode(&script_code_hex)?;

            trimmed_tx.extend_from_slice(&script_code_bytes);

            // PUSHING THE AMOUNT
            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            // PUSHING THE SEQUENCE
            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            // PUSHING THE OUTPUTS IN THE SEQUENCE

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            // PUSHING THE LOCKTIME
            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }

        if input_type == "P2WSH" {
            // println!("P2WSH");
            trimmed_tx.extend(&tx.version.to_le_bytes());

            // PUSHING HASHPREVOUTS AND HASHSEQUENCE
            let mut prevouts: Vec<u8> = Vec::new();
            let mut sequence: Vec<u8> = Vec::new();
            for input_index in 0..tx.vin.len() {
                let mut txid_bytes_reversed = hex::decode(&tx.vin[input_index].txid)?;
                txid_bytes_reversed.reverse();

                prevouts.extend_from_slice(&txid_bytes_reversed);
                prevouts.extend(&tx.vin[input_index].vout.to_le_bytes());

                sequence.extend(&tx.vin[input_index].sequence.to_le_bytes());
            }
            let hashprevouts = double_sha256(&prevouts);
            let hashsequence = double_sha256(&sequence);

            trimmed_tx.extend_from_slice(&hashprevouts);
            trimmed_tx.extend_from_slice(&hashsequence);

            // OUTPOINTS FOR THE INPUT BEING VERIFIED

            // SUBPARTS :-

            // PUSING THE REVERSED TXID
            let mut txid_bytes_reversed_sig = hex::decode(&tx.vin[tx_input_index].txid)?;
            txid_bytes_reversed_sig.reverse();

            trimmed_tx.extend_from_slice(&txid_bytes_reversed_sig);
            trimmed_tx.extend(tx.vin[tx_input_index].vout.to_le_bytes());

            // SCRIPT CODE

            // EXTRACTING THE WITNESS SCRIPT FROM THE WITNESS

            let witness = tx.vin[tx_input_index].witness.clone().unwrap();

            let witness_script = witness.last().cloned().unwrap();

            let script_code_bytes = hex::decode(&witness_script)?;

            trimmed_tx.push(script_code_bytes.len().try_into()?);
            trimmed_tx.extend_from_slice(&script_code_bytes);

            // PUSHING THE AMOUNT
            trimmed_tx.extend(tx.vin[tx_input_index].prevout.value.to_le_bytes());

            // PUSHING THE SEQUENCE
            trimmed_tx.extend(tx.vin[tx_input_index].sequence.to_le_bytes());

            // PUSHING THE OUTPUTS IN THE SEQUENCE

            let mut outputs: Vec<u8> = Vec::new();
            for output in tx.vout.iter() {
                outputs.extend(output.value.to_le_bytes());

                let scriptpubkey_bytes = hex::decode(&output.scriptpubkey)?;
                outputs.push(scriptpubkey_bytes.len().try_into()?);
                outputs.extend_from_slice(&scriptpubkey_bytes);
            }

            let hash_outputs = double_sha256(&outputs);

            trimmed_tx.extend_from_slice(&hash_outputs);

            // PUSHING THE LOCKTIME
            trimmed_tx.extend(tx.locktime.to_le_bytes());
        }
    } else {
        // println!("NEW SIGHASH FOUND: {}", sighash_type);
        // println!("txid: {:?}", tx.vin[0].txid);
    }

    // TRASNSACTION BYTE SEQUENCE READY

    Ok(trimmed_tx)
}

pub fn verify_tx(tx: Transaction) -> Result<bool> {
    let _p2pkh = "p2pkh".to_string();
    let _p2sh = "p2sh".to_string();
    let _p2wpkh = "v0_p2wpkh".to_string();
    let _p2wsh = "v0_p2wsh".to_string();
    let _p2tr = "v1_p2tr".to_string();

    let tx_type = tx.vin[0].prevout.scriptpubkey_type.clone();
    let mut v_result = false;

    // GAS FEES CHECK
    if gas_fees_check(&tx) != true {
        // println!("TRANSACTION INVALID: LOW GAS FEES");
        return Ok(false);
    }

    for input_index in 0..tx.vin.len() {
        if tx.vin[input_index].prevout.scriptpubkey_type != tx_type {
            return Ok(false);
        }
    }

    if tx_type == _p2pkh {
        for input_index in 0..tx.vin.len() {
            match input_verification_p2pkh(tx.clone(), input_index) {
                Ok(false) => {
                    // println!("TRASNACTION: INVALID");
                    return Ok(false);
                }
                Ok(true) => {
                    v_result = true;
                }
                Err(_) => {
                    // println!("TRASNACTION: INVALID");
                    return Ok(false);
                }
            }
        }
    }
    // if tx_type == _p2sh {
    //     for input_index in 0..tx.vin.len() {
    //         match input_verification_p2sh(input_index, tx.clone()) {
    //             Ok(false) => {
    //                 // println!("TRASNACTION: INVALID");
    //                 return Ok(false);
    //             }

    //             Ok(true) => {
    //                 v_result = true;
    //             }

    //             Err(_) => {
    //                 // println!("TRASNACTION: INVALID");
    //                 return Ok(false);
    //             }
    //         }
    //     }
    // }
    if tx_type == _p2wpkh {
        for input_index in 0..tx.vin.len() {
            match input_verification_p2wpkh(input_index, tx.clone()) {
                Ok(false) => {
                    // println!("TRASNACTION: INVALID");
                    return Ok(false);
                }

                Ok(true) => {
                    v_result = true;
                }

                Err(_) => {
                    // println!("TRASNACTION: INVALID");
                    return Ok(false);
                }
            }
        }
    }
    if tx_type == _p2wsh {
        for input_index in 0..tx.vin.len() {
            match input_verification_p2wsh(input_index, tx.clone()) {
                Ok(false) => {
                    // println!("TRASNACTION: INVALID");
                    return Ok(false);
                }

                Ok(true) => {
                    v_result = true;
                }

                Err(_) => {
                    // println!("TRASNACTION: INVALID");
                    return Ok(false);
                }
            }
        }
    }
    if tx_type == _p2tr {
        // CHECK IF THE WITNESS ITEMS LENGTH IS <255

        for input in tx.vin.iter() {
            let witness = input.witness.clone().unwrap();
            for item in witness {
                let item_bytes = hex::decode(&item)?;
                if item_bytes.len() >= 255 {
                    return Ok(false);
                }
            }
        }

        v_result = true;
    }

    Ok(v_result)
}

fn gas_fees_check(tx: &Transaction) -> bool {
    let mut s_sats: u64 = 0;
    let mut r_sats: u64 = 0;

    for input_index in 0..tx.vin.len() {
        if tx.vin[input_index].prevout.value <= 0 {
            return false;
        }
        s_sats += tx.vin[input_index].prevout.value;
    }

    for output_index in 0..tx.vout.len() {
        if tx.vout[output_index].value <= 0 {
            return false;
        }
        r_sats += tx.vout[output_index].value;
    }

    if s_sats - r_sats < 2000 {
        return false;
    } else {
        return true;
    }
}

pub fn all_transaction_verification() -> Result<()> {
    // let mut s_count = 0;
    // let mut f_count = 0;
    // let mut d_spends = 0;
    let mempool_dir = "./mempool";
    let mut spends: HashMap<String, String> = HashMap::new();
    'outer: for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            match fs::read_to_string(path) {
                Ok(contents) => {
                    match serde_json::from_str::<Transaction>(&contents) {
                        Ok(transaction) => {
                            // Check if all inputs' prevout scriptpubkey_type are .p2sh
                            let all_p2sh = true;
                            if all_p2sh {
                                for input in &transaction.vin {
                                    let input_key = format!("{}{}", input.txid, input.vout);
                                    match spends.get(&input_key) {
                                        Some(existing_txid)
                                            if path.display().to_string() != *existing_txid =>
                                        {
                                            // d_spends += 1;
                                            continue 'outer;
                                        }
                                        _ => {
                                            spends.insert(input_key, path.display().to_string());
                                        }
                                    }
                                }

                                let result = verify_tx(transaction)?;

                                if result == true {
                                    // s_count += 1;
                                    // println!("SUCCESSFULL");
                                    if let Some(filename) = path.file_name() {
                                        let valid_mempool_dir = Path::new("./valid-mempool");
                                        let destination_path = valid_mempool_dir.join(filename);
                                        fs::copy(&path, &destination_path)?;
                                    }
                                } else {
                                    // f_count += 1;
                                    // println!("FAILED");
                                }

                                // println!("\n\n");
                            }
                        }
                        Err(_e) => {
                            // println!("Failed to parse JSON: {}", e);
                        }
                    }
                }
                Err(_e) => {}
            }
        }
    }

    // println!("success: {}", s_count);
    // println!("failure: {}", f_count);
    // println!("doubles: {}", d_spends);

    Ok(())
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs, path::Path};

    use walkdir::WalkDir;

    use super::*;

    #[test]
    fn test_all_transaction_verification() -> Result<()> {
        // let mut s_count = 0;
        // let mut f_count = 0;
        // let mut d_spends = 0;
        let mempool_dir = "./mempool2";
        let mut spends: HashMap<String, String> = HashMap::new();
        'outer: for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                match fs::read_to_string(path) {
                    Ok(contents) => {
                        match serde_json::from_str::<Transaction>(&contents) {
                            Ok(transaction) => {
                                // Check if all inputs' prevout scriptpubkey_type are .p2sh
                                let all_p2sh = true;
                                if all_p2sh {
                                    for input in &transaction.vin {
                                        let input_key = format!("{}{}", input.txid, input.vout);
                                        match spends.get(&input_key) {
                                            Some(existing_txid)
                                                if path.display().to_string() != *existing_txid =>
                                            {
                                                // d_spends += 1;
                                                continue 'outer;
                                            }
                                            _ => {
                                                spends
                                                    .insert(input_key, path.display().to_string());
                                            }
                                        }
                                    }

                                    let result = verify_tx(transaction)?;

                                    if result == true {
                                        // s_count += 1;
                                        if let Some(filename) = path.file_name() {
                                            let valid_mempool_dir = Path::new("./valid-mempool");
                                            let destination_path = valid_mempool_dir.join(filename);
                                            fs::copy(&path, &destination_path)?;
                                        }
                                    } else {
                                        // f_count += 1;
                                    }

                                    // println!("\n\n");
                                }
                            }
                            Err(_e) => {
                                // println!("Failed to parse JSON: {}", e);
                            }
                        }
                    }
                    Err(_e) => {}
                }
            }
        }

        // println!("success: {}", s_count);
        // println!("failure: {}", f_count);
        // println!("doubles: {}", d_spends);

        Ok(())
    }
}
