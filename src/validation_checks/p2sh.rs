use std::vec;

use hex;
use log::info;

use crate::validation_checks::hash160;
use crate::validation_checks::op_checkmultisig;
use crate::validation_checks::op_checksig;

use crate::{error::Result, transaction::Transaction};

// IMPUT VERIFICATION FOR P2SH
pub fn input_verification_p2sh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();

    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    let scriptsig_asm = match tx.vin[tx_input_index].scriptsig_asm.clone() {
        Some(value) => value,
        None => {
            return Ok(false);
        }
    };

    let inner_redeemscript_asm = match tx.vin[tx_input_index].inner_redeemscript_asm.clone() {
        Some(value) => value,
        None => {
            return Ok(false);
        }
    };

    Ok(script_execution_p2sh(
        scriptpubkey_asm,
        witness,
        scriptsig_asm,
        inner_redeemscript_asm,
        tx,
        tx_input_index,
    )?)
}

// SCRIPT EXECUTION
fn script_execution_p2sh(
    scriptpubkey_asm: String,
    witness: Vec<String>,
    scriptsig_asm: String,
    inner_redeemscript_asm: String,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    let mut script_result: bool = false;
    let input_type: &str;

    // DEFINING THE SCRIPT TYPE OF THE VERIFYING INPUT
    if witness.len() == 0 {
        input_type = "NON_SEGWIT";
    } else if witness.len() == 2 {
        input_type = "P2SH-P2WPKH";
    } else {
        input_type = "P2SH-P2WSH";
    }

    let mut stack = Vec::new();

    // EXECUTING SCRIPT SIG ASM
    let scriptsig_asm_opcodes: Vec<&str> = scriptsig_asm.split_whitespace().collect();
    for opcode_index in 0..scriptsig_asm_opcodes.len() {
        let is_pushbytes = scriptsig_asm_opcodes[opcode_index].starts_with("OP_PUSHBYTES");
        let is_pushdata = scriptsig_asm_opcodes[opcode_index].starts_with("OP_PUSHDATA");

        match scriptsig_asm_opcodes[opcode_index] {
            "OP_0" => {
                // Push an empty array of bytes in the stack
                stack.push(vec![0 as u8]);
            }
            _ if is_pushbytes => {
                // PUSHING SIGNATURES OR REDEEM SCRIPT IN SCRIPT SIG ASM
                stack.push(hex::decode(&scriptsig_asm_opcodes[opcode_index + 1])?);
            }

            _ if is_pushdata => {
                // REDEEM SCRIPT
                stack.push(hex::decode(&scriptsig_asm_opcodes[opcode_index + 1])?);
            }
            _ => continue,
        }
    }

    // EXECUTING SCRIPT PUB KEY
    let scriptpubkey_asm_opcodes: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    for opcode_index in 0..scriptpubkey_asm_opcodes.len() {
        match scriptpubkey_asm_opcodes[opcode_index] {
            "OP_HASH160" => {
                let hash = hash160(&stack.pop().expect("STACK UNDERFLOW: OP_HASH160"));
                stack.push(hash);
            }
            "OP_PUSHBYTES_20" => {
                stack.push(
                    hex::decode(&scriptpubkey_asm_opcodes[opcode_index + 1])
                        .expect("DECODING: FAILED"),
                );
            }
            "OP_EQUAL" => {
                let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUAL");
                let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUAL");

                if a != b {
                    return Ok(false);
                }
            }
            _ => continue,
        }
    }


    // EXECUTING THE INNER REDEEM SCRIPT AS PER THE SCRIPT TYPE
    if input_type == "NON_SEGWIT" {

        // EXECUTE INNER REDEEM SCRIPT ASM
        let inner_redeemscript_asm_opcodes: Vec<&str> =
            inner_redeemscript_asm.split_whitespace().collect();

        for opcode_index in 0..inner_redeemscript_asm_opcodes.len() {
            let is_pushbytes =
                inner_redeemscript_asm_opcodes[opcode_index].starts_with("OP_PUSHBYTES");

            let is_pushdata =
                inner_redeemscript_asm_opcodes[opcode_index].starts_with("OP_PUSHDATA");

            let is_equal = inner_redeemscript_asm_opcodes[opcode_index].starts_with("OP_EQUAL");

            match inner_redeemscript_asm_opcodes[opcode_index] {
                "OP_PUSHNUM_2" => stack.push(vec![2u8]),
                "OP_PUSHNUM_3" => stack.push(vec![3u8]),
                "OP_PUSHNUM_4" => stack.push(vec![4u8]),

                _ if is_pushbytes => {
                    // PUSHING THE PUBLIC KEYS, SIGNATURES IN THE STACK
                    stack.push(
                        hex::decode(&inner_redeemscript_asm_opcodes[opcode_index + 1])
                            .expect("DECODING: FAILED"),
                    );
                }

                _ if is_pushdata => {
                    // PUSHING DATA IN THE STACK
                    stack.push(
                        hex::decode(&inner_redeemscript_asm_opcodes[opcode_index + 1])
                            .expect("DECODING: FAILED"),
                    );
                }

                "OP_0" => {
                    // Push an empty array of bytes in the stack
                    stack.push(vec![0 as u8]);
                }

                "OP_CSV" => {
                    // CHECK THE PREV PUSHED DATA WITH THE SEQUENCE OF THE INPUT, LATER
                    continue;
                }

                "OP_DROP" => {
                    // POPS THE TOP ELEMENT OF THE STACK
                    stack.pop().expect("SATCK UNDERFLOW: OP_DROP");
                }

                "OP_DUP" => stack.push(stack.last().cloned().expect("STACK UNDERFLOW")),

                "OP_HASH160" => {
                    let pk = stack.pop().expect("STACK UNDERFLOW");
                    stack.push(hash160(&pk));
                }

                _ if is_equal => {
                    let a = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");
                    let b = stack.pop().expect("STACK UNDERFLOW: OP_EQUALVERIFY");

                    if a == b {
                        // println!("REDEEM EQUAL: SUCCESSFULL");
                        script_result = true;
                    } else {
                        // println!("REDEEM EQUAL: FAILED");
                        return Ok(false);
                    }
                }

                "OP_CHECKSIGVERIFY" => {
                    let result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if result == false {
                        // println!("OP_CHECKSIGVERIFY: FAILED");
                        return Ok(false);
                    }
                }

                "OP_DEPTH" => {
                    // PUSH THE EXISTING LENGTH OF THE STACK
                    stack.push(vec![0 as u8]);
                }

                "OP_CHECKSIG" => {
                    // IMPLEMENT CHECKSIG OPCODE
                    script_result =
                        op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;
                }

                "OP_CHECKMULTISIG" => {
                    // IMPLEMENT CHECKMULTISIG OPCODE
                    script_result =
                        op_checkmultisig(&mut stack, tx.clone(), tx_input_index, input_type)?;
                }
                _ => continue,
            }
        }
    }

    if input_type == "P2SH-P2WPKH" {
        // EXECUTE WITNESS

        // PUSH SIGNATURE
        stack.push(hex::decode(&witness[0]).expect("DECODING: FAILED"));

        // PUSH PUBLIC KEY
        stack.push(hex::decode(&witness[1]).expect("DECODING: FAILED"));

        // IMPLICIT OPCODE EXECUTION (OP_DUP, OP_HASH160, OP_PUSHBYTES_20, OP_EQUALVERIFY, OP_CHECKSIG)

        // OP_DUP
        stack.push(stack.last().cloned().expect("STACK UNDERFLOW"));

        // OP_HASH160
        let pk = stack.pop().expect("STACK UNDERFLOW");
        stack.push(hash160(&pk));

        // EXECUTE INNER REDEEM SCRIPT (OP_PUSHBYTES_20)
        let inner_redeemscript_opcodes: Vec<&str> =
            inner_redeemscript_asm.split_whitespace().collect();

        for opcode_index in 0..inner_redeemscript_opcodes.len() {
            match inner_redeemscript_opcodes[opcode_index] {
                "OP_0" => info!("SEGWIT VERSION: 0"),

                "OP_PUSHBYTES_20" => {
                    stack.push(
                        hex::decode(&inner_redeemscript_opcodes[opcode_index + 1])
                            .expect("DECODING: FAILED"),
                    );
                }
                _ => continue,
            }
        }

        // OP_EQUALVERIFY
        let a = stack.pop().expect("STACK UNDERFLOW");
        let b = stack.pop().expect("STACK UNDERFLOW");

        if a != b {
            return Ok(false);
        }

        // OP_CHECKSIG
        script_result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;
    }

    if input_type == "P2SH-P2WSH" {
        // EXECUTE WITNESS

        // PUSH SIGNATURES

        for index in 0..witness.len() - 1 {
            stack.push(hex::decode(&witness[index])?);
        }

        // EXECUTING THE WITNESS SCRIPT

        let witness_script_bytes = hex::decode(&witness.last().cloned().expect("SCRIPT MISSING"))?;

        let mut index = 0;

        while index < witness_script_bytes.len() {
            let opcode = witness_script_bytes[index];
            index += 1;

            match opcode {
                82 => {
                    // OP_2 SIGNATURE COUNT
                    stack.push(vec![2u8]);
                }
                _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                    // OP_PUSHBYTES_33
                    if index + opcode as usize <= witness_script_bytes.len() {
                        let bytes = witness_script_bytes[index..index + opcode as usize].to_vec();
                        stack.push(bytes);
                        index += opcode as usize;
                    }
                }

                83 => {
                    // OP_3 PUBLIC KEY COUNT
                    stack.push(vec![3u8]);
                }

                174 => {
                    // OP_CHECKMULTISIG
                    script_result =
                        op_checkmultisig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if script_result == true {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8])
                    }
                }

                173 => {
                    // OP_CHECKSIGVERIFY
                    let result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                    if result == true {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8]);
                    }

                    // OP_VERIFY

                    let top = stack.pop().unwrap();
                    if top == vec![1u8] {
                        script_result = true;
                        continue;
                    } else {
                        return Ok(false);
                    }
                }

                172 => {
                    // OP_CHECKSIG

                    let sig_length = stack[stack.len() - 1].len();

                    if sig_length <= 75 && sig_length >= 70 {
                        script_result =
                            op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                        if script_result == true {
                            stack.push(vec![1u8]);
                        } else {
                            stack.push(vec![0u8])
                        }
                    } else {
                        stack.push(vec![0u8]);
                    }
                }

                100 => {
                    // OP_NOTIF
                    if stack.last().cloned().unwrap_or(vec![254u8]) == vec![0u8] {
                    } else {
                        if witness_script_bytes[index] <= 75 {
                            if witness_script_bytes[index] >= 1 {
                                index += witness_script_bytes[index] as usize;
                            }
                        } else if witness_script_bytes[index] == 103 {
                            // EXECUTE THE NEXT STATEMENT
                        } else if witness_script_bytes[index] == 104 {
                            stack.pop();
                            continue;
                        }
                    }
                }

                99 => {
                    // OP_IF
                    if stack.last().cloned().unwrap_or(vec![254u8]) == vec![1u8] {
                    } else {
                        if witness_script_bytes[index] <= 75 {
                            if witness_script_bytes[index] >= 1 {
                                index += witness_script_bytes[index] as usize;
                            }
                        } else if witness_script_bytes[index] == 103 {
                            // EXECUTE THE NEXT STATEMENT
                        } else if witness_script_bytes[index] == 104 {
                            stack.pop();
                            continue;
                        }
                    }
                }

                115 => {
                    // OP_IFDUP
                    if stack.last().cloned().unwrap_or(vec![254u8]) != vec![0u8] {
                        stack.push(stack.last().cloned().expect("STACK UNDERFLOW"))
                    }
                }

                _ => continue,
            }
        }
    }
    Ok(script_result)
}

// TO TEST MY CODE DURING DEVELOPMENT
#[cfg(test)]
mod test {
    use std::fs;

    use walkdir::WalkDir;

    use super::*;

    #[test]
    fn test_script_execution_p2sh() -> Result<()> {
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
                                    input.prevout.scriptpubkey_type == "p2sh".to_string()
                                });
                                if all_p2sh {
                                    let result = script_execution_p2sh(
                                        transaction.vin[0].prevout.scriptpubkey_asm.clone(),
                                        transaction.vin[0]
                                            .witness
                                            .clone()
                                            .unwrap_or(vec!["".to_string()]),
                                        transaction.vin[0].scriptsig_asm.clone().unwrap(),
                                        transaction.vin[0].inner_redeemscript_asm.clone().unwrap(),
                                        transaction,
                                        0,
                                    )?;

                                    if result == true {
                                    } else {
                                    }
                                }
                            }
                            Err(_e) => {}
                        }
                    }
                    Err(_e) => {}
                }
            }
        }
        Ok(())
    }
}
