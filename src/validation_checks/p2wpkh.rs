use hex;

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

// TO TEST MY CODE DURING DEVELOPMENT
#[cfg(test)]
mod test {
    use std::fs;

    use walkdir::WalkDir;

    use super::*;

    #[test]
    fn test_script_execution_p2wpkh() -> Result<()> {
        // let mut s_count = 0;
        // let mut f_count = 0;
        let mempool_dir = "./mempool";
        for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                match fs::read_to_string(path) {
                    Ok(contents) => {
                        match serde_json::from_str::<Transaction>(&contents) {
                            Ok(transaction) => {
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
                                    } else {
                                    }

                                }
                            }
                            Err(_e) => {
                            }
                        }
                    }
                    Err(_e) => {}
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test2() -> Result<()> {
        let path =
            "./mempool/0a5d6ddc87a9246297c1038d873eec419f04301197d67b9854fa2679dbe3bd65.json";

        // Read the JSON file
        let data = fs::read_to_string(path).expect("Unable to read file");

        // Deserialize JSON into Rust data structures
        let transaction: Transaction = serde_json::from_str(&data)?;

        let tx = transaction.clone();
        let result = script_execution_p2wpkh(tx.vin[0].witness.clone().unwrap(), tx, 0)?;

        println!("{}", result);

        Ok(())
    }
}

