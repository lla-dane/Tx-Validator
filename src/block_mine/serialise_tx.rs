use std::{collections::HashMap, fs, os::fd::RawFd, path::Path};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{
    error::Result,
    transaction::{self, Input, Transaction},
};

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(data)).to_vec()
}

pub fn create_txid_tx_map() -> Result<Vec<(String, Transaction, String, usize, u64)>> {
    // let path = Path::new("./valid-mempool");
    // clear_directory(path)?;

    let v_mempool_dir = "./valid-mempool";
    let mut map: Vec<(String, Transaction, String, usize, u64)> = Vec::new();

    for entry in WalkDir::new(v_mempool_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            match fs::read_to_string(path) {
                Ok(contents) => match serde_json::from_str::<Transaction>(&contents) {
                    Ok(transaction) => {
                        let (result, serialised_tx, serialised_wtx, tx_weight, fees) =
                            serialise_tx(&transaction)?;

                        if result == true {
                            let mut txid = double_sha256(&serialised_tx);
                            let mut wtxid = double_sha256(&serialised_wtx);

                            txid.reverse();
                            wtxid.reverse();

                            let txid = hex::encode(txid);
                            let wtxid = hex::encode(wtxid);

                            // Find the correct position to insert the transaction based on its fees
                            let position = map
                                .iter()
                                .position(|(_, _, _, _, gas_fees)| fees > *gas_fees)
                                .unwrap_or(map.len());
                            map.insert(position, (txid, transaction, wtxid, tx_weight, fees));
                        }
                    }
                    Err(e) => {}
                },
                Err(e) => {}
            }
        }
    }

    Ok(map)
}

fn serialise_tx(tx: &Transaction) -> Result<(bool, Vec<u8>, Vec<u8>, usize, u64)> {
    let tx_type;
    if tx.vin[0].witness == None {
        tx_type = "LEGACY";
    } else {
        tx_type = "SEGWIT";
    }

    let mut fees = 0;
    let mut non_witness_bytes = 0;
    let mut witness_bytes = 0;

    // CALCULATE GAS FEES
    for input in tx.vin.iter() {
        fees += input.prevout.value;
    }

    for output in tx.vout.iter() {
        fees -= output.value;
    }

    let mut raw_tx: Vec<u8> = Vec::new();
    let mut raw_wtx: Vec<u8> = Vec::new();

    if tx_type == "LEGACY" {
        // VERSION
        raw_tx.extend(tx.version.to_le_bytes());
        non_witness_bytes += 4;

        // INPUT COUNT
        if tx.vin.len() >= 50 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }

        raw_tx.push(tx.vin.len().try_into()?);
        non_witness_bytes += 1;

        // INPUTS
        for input in tx.vin.iter() {
            // TXID REVERSED
            let txid = hex::decode(&input.txid.clone())?;
            // SCRIPT SIG
            let script_sig = hex::decode(&input.scriptsig.clone().unwrap())?;
            let script_sig_len = script_sig.len();

            raw_tx.extend_from_slice(&txid);
            raw_tx.extend(input.vout.to_le_bytes());
            raw_tx.push(script_sig.len().try_into()?);
            raw_tx.extend_from_slice(&script_sig);
            raw_tx.extend(input.sequence.to_le_bytes());

            non_witness_bytes += 32 + 4 + 1 + script_sig_len + 4;
        }

        // OUTPUT COUNT

        if tx.vout.len() >= 50 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }

        raw_tx.push(tx.vout.len().try_into()?);

        non_witness_bytes += 1;

        // OUTPUTS
        for output in tx.vout.iter() {
            // SCRIPT PUB KEY
            let scriptpubkey = hex::decode(&output.scriptpubkey.clone())?;
            let scriptpubkey_len = scriptpubkey.len();

            raw_tx.extend(output.value.to_le_bytes());
            raw_tx.push(scriptpubkey.len().try_into()?);
            raw_tx.extend_from_slice(&scriptpubkey);

            non_witness_bytes += 8 + 1 + scriptpubkey_len;
        }

        // LOCKTIME
        raw_tx.extend(tx.locktime.to_le_bytes());
        non_witness_bytes += 4;

        raw_wtx = raw_tx.clone();
    } else {
        // VERSION
        raw_tx.extend(tx.version.to_le_bytes());
        raw_wtx.extend(tx.version.to_le_bytes());

        non_witness_bytes += 4;

        // MARKER FLAG IN WTX ONLY
        let marker = 00;
        let flag = 01;
        raw_wtx.push(marker.try_into()?);
        raw_wtx.push(flag.try_into()?);

        witness_bytes += 1 + 1;

        // INPUT COUNT
        if tx.vin.len() >= 50 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }
        raw_tx.push(tx.vin.len().try_into()?);
        raw_wtx.push(tx.vin.len().try_into()?);

        non_witness_bytes += 1;

        // INPUTS
        for input in tx.vin.iter() {
            // TXID REVERSED
            let txid = hex::decode(&input.txid.clone())?;

            // SCRIPT SIG
            let script_sig = hex::decode(&input.scriptsig.clone().unwrap())?;
            let script_sig_len = script_sig.len();

            raw_tx.extend_from_slice(&txid);
            raw_tx.extend(input.vout.to_le_bytes());

            raw_wtx.extend_from_slice(&txid);
            raw_wtx.extend(input.vout.to_le_bytes());

            non_witness_bytes += 32 + 4;

            if script_sig.len() >= 255 {
                return Ok((false, Vec::new(), Vec::new(), 0, 0));
            }

            raw_tx.push(script_sig.len().try_into()?);
            raw_wtx.push(script_sig.len().try_into()?);

            non_witness_bytes += 1;

            if script_sig.len() != 0 {
                raw_tx.extend_from_slice(&script_sig);
                raw_wtx.extend_from_slice(&script_sig);

                non_witness_bytes += script_sig_len;
            }
            raw_tx.extend(input.sequence.to_le_bytes());
            raw_wtx.extend(input.sequence.to_le_bytes());

            non_witness_bytes += 4;
        }

        // OUTPUT COUNT
        if tx.vout.len() >= 255 {
            return Ok((false, Vec::new(), Vec::new(), 0, 0));
        }
        raw_tx.push(tx.vout.len().try_into()?);
        raw_wtx.push(tx.vout.len().try_into()?);

        non_witness_bytes += 1;

        // OUTPUTS
        for output in tx.vout.iter() {
            // SCRIPT PUB KEY
            let scriptpubkey = hex::decode(&output.scriptpubkey.clone())?;
            let scriptpubkey_len = scriptpubkey.len();

            raw_tx.extend(output.value.to_le_bytes());
            raw_wtx.extend(output.value.to_le_bytes());

            non_witness_bytes += 8;

            if scriptpubkey.len() >= 50 {
                return Ok((false, Vec::new(), Vec::new(), 0, 0));
            }
            raw_tx.push(scriptpubkey.len().try_into()?);
            raw_wtx.push(scriptpubkey.len().try_into()?);
            raw_tx.extend_from_slice(&scriptpubkey);
            raw_wtx.extend_from_slice(&scriptpubkey);

            non_witness_bytes += 1 + scriptpubkey_len;
        }

        // WITNESS ONLY IN WTX
        for input in tx.vin.iter() {
            let witness = input.witness.clone().unwrap();
            let witness_len = witness.len();

            raw_wtx.push(witness.len().try_into()?);

            witness_bytes += 1;

            for item in witness {
                let item_bytes = hex::decode(&item)?;
                let item_bytes_len = item_bytes.len();
                raw_wtx.push(item_bytes.len().try_into()?);
                raw_wtx.extend_from_slice(&item_bytes);

                witness_bytes += 1 + item_bytes_len;
            }
        }

        // LOCKTIME
        raw_tx.extend(tx.locktime.to_le_bytes());
        raw_wtx.extend(tx.locktime.to_le_bytes());

        non_witness_bytes += 4;
    }

    let tx_weight = (non_witness_bytes * 4) + (witness_bytes);

    Ok((true, raw_tx, raw_wtx, tx_weight, fees))
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;

    #[test]
    fn test2() -> Result<()> {
        let path =
            "./mempool/9794a97e79dcec4425aaa1dbf448b7a99d19c6e47d831c5b31574ec785193617.json";

        // Read the JSON file
        let data = fs::read_to_string(path).expect("Unable to read file");

        // Deserialize JSON into Rust data structures
        let transaction: Transaction = serde_json::from_str(&data)?;

        let scriptsig_asm = transaction.clone().vin[0]
            .scriptsig_asm
            .clone()
            .expect("ASM: MISSING");

        let tx = transaction.clone();
        let result = serialise_tx(&transaction)?;

        Ok(())
    }

    #[test]
    fn test1() -> Result<()> {
        let map = create_txid_tx_map()?;
        let mut total_weight = 0;

        for (_, _, _, weight, _) in map {
            // println!("{}", weight);
            total_weight += weight;
        }
        // println!("{}", total_weight);

        Ok(())
    }

    #[test]
    fn test5() -> Result<()> {
        let v_mempool_dir = "./valid-mempool";

        for entry in WalkDir::new(v_mempool_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            // println!("{}", path.display().to_string());
        }

        Ok(())
    }
}
