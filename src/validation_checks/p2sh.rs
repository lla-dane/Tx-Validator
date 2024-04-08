use std::vec;

use hex;
use log::info;

use crate::validation_checks::hash160;
use crate::validation_checks::op_checkmultisig;
use crate::validation_checks::op_checksig;

use crate::{error::Result, transaction::Transaction};

pub fn input_verification_p2sh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();

    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    let scriptsig_asm = match tx.vin[tx_input_index].scriptsig_asm.clone() {
        Some(value) => value,
        None => {
            // eprintln!("SCRIPT SIG ASM: MISSING");
            return Ok(false);
        }
    };

    let inner_redeemscript_asm = match tx.vin[tx_input_index].inner_redeemscript_asm.clone() {
        Some(value) => value,
        None => {
            // eprintln!("INNER REDEEM SCRIPT: MISSING");
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

    // println!("SCRIPTSIG: SUCCESSFULL");

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
                    // println!("OP_EQUAL: FAILED");
                    return Ok(false);
                } else {
                    // println!("SCRIPTPUBKKEY: SUCCESSFULL");
                }
            }
            _ => continue,
        }
    }

    if input_type == "NON_SEGWIT" {
        // println!("NON-SEGWIT");

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

        // println!("P2SH-P2WPKH");

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
            // println!("OP_EQUALVERIFY: FAILED");
            return Ok(false);
        }

        // OP_CHECKSIG
        script_result = op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;
        // println!("script_result: {}", script_result);
    }

    if input_type == "P2SH-P2WSH" {
        // EXECUTE WITNESS
        // println!("P2SH-P2WSH");

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
                    // println!("OP_NOTIF: SUCCESSFULL");
                }

                99 => {
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
                    // println!("OP_IF: SUCESSFULL");
                }

                115 => {
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

#[cfg(test)]
mod test {
    use std::fs;

    use walkdir::WalkDir;

    use super::*;

    #[test]
    fn test_script_execution_p2sh() -> Result<()> {
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
                                        // s_count += 1;
                                    } else {
                                        // f_count += 1;
                                    }

                                    // println!("\n\n");
                                }
                            }
                            Err(_e) => {
                                // println!("Failed to parse JSON: {}", _e);
                            }
                        }
                    }
                    Err(_e) => {}
                }
            }
        }

        // println!("success: {}", s_count);
        // println!("failure: {}", f_count);

        Ok(())
    }
}

// let dummy_tx = Transaction {
//     version: 2,
//     locktime: 833580,
//     vin: vec![
//         Input {
//             txid: "ffa14af9d498b93bcee6c87162d0c02d7a1c692278d1280039eb1952252e500f".to_string(),
//             vout: 2,
//             prevout: Prevout {
//                 scriptpubkey: "a914c687296f552aac1ec0755fc9571e4e3ce9f55ddd87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 c687296f552aac1ec0755fc9571e4e3ce9f55ddd OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3KnjdjfrbddVytAkmBpcDXa3Q2xMC3TQY2".to_string(),
//                 value: 10000,
//             },
//             scriptsig: Some("483045022100e188cc2532d35d905718fe5b51f10164dadfc226d3190f446c87720677a2396c022050db86f1ef01a266e045be3d287830bcc3081e1c51897e23e978bbfc75623bb3012102a8dec57acd81beec3b736ab6cd98a20b7610eb2aaf18c9008dbe47d5e7c9dc751f03070040b27576a9148e937cbb57b7239f4e3e6f4def6d3e084d2adcb688ac".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_72 3045022100e188cc2532d35d905718fe5b51f10164dadfc226d3190f446c87720677a2396c022050db86f1ef01a266e045be3d287830bcc3081e1c51897e23e978bbfc75623bb301 OP_PUSHBYTES_33 02a8dec57acd81beec3b736ab6cd98a20b7610eb2aaf18c9008dbe47d5e7c9dc75 OP_PUSHBYTES_31 03070040b27576a9148e937cbb57b7239f4e3e6f4def6d3e084d2adcb688ac".to_string()),
//             witness: Some(Vec::new()),
//             is_coinbase: false,
//             sequence: 4194311,
//             inner_redeemscript_asm: Some("OP_PUSHBYTES_3 070040 OP_CSV OP_DROP OP_DUP OP_HASH160 OP_PUSHBYTES_20 8e937cbb57b7239f4e3e6f4def6d3e084d2adcb6 OP_EQUALVERIFY OP_CHECKSIG".to_string()),
//         },
//         Input {
//             txid: "3b75145765105973b510f08e596438085456caca55616f0b0f1e982e2658e10d".to_string(),
//             vout: 1,
//             prevout: Prevout {
//                 scriptpubkey: "a914c687296f552aac1ec0755fc9571e4e3ce9f55ddd87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 c687296f552aac1ec0755fc9571e4e3ce9f55ddd OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3KnjdjfrbddVytAkmBpcDXa3Q2xMC3TQY2".to_string(),
//                 value: 4000,
//             },
//             scriptsig: Some("483045022100c420b2fe3df5285949e7f8b86752eb693c97ebf990b761481aa9ade8d7841b0802207f16fa85ab5f06c221001ac1c3b1096850175885f09f9fc46354bb1722a95417012102a8dec57acd81beec3b736ab6cd98a20b7610eb2aaf18c9008dbe47d5e7c9dc751f03070040b27576a9148e937cbb57b7239f4e3e6f4def6d3e084d2adcb688ac".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_72 3045022100c420b2fe3df5285949e7f8b86752eb693c97ebf990b761481aa9ade8d7841b0802207f16fa85ab5f06c221001ac1c3b1096850175885f09f9fc46354bb1722a9541701 OP_PUSHBYTES_33 02a8dec57acd81beec3b736ab6cd98a20b7610eb2aaf18c9008dbe47d5e7c9dc75 OP_PUSHBYTES_31 03070040b27576a9148e937cbb57b7239f4e3e6f4def6d3e084d2adcb688ac".to_string()),
//             witness: Some(Vec::new()),
//             is_coinbase: false,
//             sequence: 4194311,
//             inner_redeemscript_asm: Some("OP_PUSHBYTES_3 070040 OP_CSV OP_DROP OP_DUP OP_HASH160 OP_PUSHBYTES_20 8e937cbb57b7239f4e3e6f4def6d3e084d2adcb6 OP_EQUALVERIFY OP_CHECKSIG".to_string()),
//         },
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "a914d46bc1cd57d9d74ce3a97ae85d5944ef89fcf8bf87".to_string(),
//             scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 d46bc1cd57d9d74ce3a97ae85d5944ef89fcf8bf OP_EQUAL".to_string(),
//             scriptpubkey_type: "p2sh".to_string(),
//             scriptpubkey_address: Some("3M4CGJUk99Qi84z8vSM7YGVLTDWcJqk3bM".to_string()),
//             value: 9578,
//         },
//     ],
// };

// let dummy_tx = Transaction {
//         version: 1,
//         locktime: 0,
//         vin: vec![
//             Input {
//                 txid: "9e6cdbe6be6fabca5853ea0e1230848af2268c0424cf8dcc84d6cfd5c76dda2f".to_string(),
//                 vout: 0,
//                 prevout: Prevout {
//                     scriptpubkey: "a914edf24b3b50c8102efc39d7387b177eb761d0fcf887".to_string(),
//                     scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 edf24b3b50c8102efc39d7387b177eb761d0fcf8 OP_EQUAL".to_string(),
//                     scriptpubkey_type: "p2sh".to_string(),
//                     scriptpubkey_address: "3PPAKt47YkDmESg8DXLmaZHwoV6pvcTmwD".to_string(),
//                     value: 546,
//                 },
//                 scriptsig: Some(
//                     "483045022100a8b1e46323559c355f9a30015491c6b679ca7a2a2acd2f4b69000c70e3d019a9022078b32e0b2938e7c6b8b72a0c9a310aa93806680cead3dcba062d68724fc9e442014d07024ddb01434e5452505254590300420000000000f7aa96f4a8666e988e5323c08f6f676a00165ac639346b04a62670aeddadc361bff1f0cf77001a779e6e52240b275b3ba6699a25e8db5fbc145a001c3e2c448b6a66842bdb835a4169fbc482698c250022807394f401afd13d024ef038c7f613073b03a30022f178232773f6a71112148012cc6a9ff9ff621f002ee2b15f49e017b469e433525dbfc60c4cc633850037170a424b3b8ad3ed653aafd46923516cbfa2b700371cf2c4cdf0ed6c261a0a23261971b11372a65b003bd8011632337bb161ca416a5d19037bfe849ff8003e52787fb74da2260f49100988a61851f55290cc0042a2603c1cffd89ad8a3da28216f9b20001977b80042c5b0097e92558abb9bc344c5a51618605988ae004de0f691634f17753befd95ded0aeadded392cb4004e56930251002f8a35e56f5c12dda3acccef3c0f004f42a407650c717bdcd1b356fbb1a4289ed586ae0054a28092787aa45a356c517fe9f4efede69ead500057281244eab70558353bb01ae044da04bb95cd4e005a262744990f9e193bb6c8b5d652b6759e02ad3d005ce773885e9988a5ddb3c1e37a05397bcd5eeca90065589c1592a555f265c48bb6505d43bdea15ba8b0066d95b9b63a5d1b61b5ae5e30221c3e19b29cf7300697521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad0075740087".to_string(),
//                 ),
//                 scriptsig_asm: Some(
//                     "OP_PUSHBYTES_72 01 OP_PUSHDATA2 4ddb01434e5452505254590300420000000000f7aa96f4a8666e988e5323c08f6f676a00165ac639346b04a62670aeddadc361bff1f0cf77001a779e6e52240b275b3ba6699a25e8db5fbc145a001c3e2c448b6a66842bdb835a4169fbc482698c250022807394f401afd13d024ef038c7f613073b03a30022f178232773f6a71112148012cc6a9ff9ff621f002ee2b15f49e017b469e433525dbfc60c4cc633850037170a424b3b8ad3ed653aafd46923516cbfa2b700371cf2c4cdf0ed6c261a0a23261971b11372a65b003bd8011632337bb161ca416a5d19037bfe849ff8003e52787fb74da2260f49100988a61851f55290cc0042a2603c1cffd89ad8a3da28216f9b20001977b80042c5b0097e92558abb9bc344c5a51618605988ae004de0f691634f17753befd95ded0aeadded392cb4004e56930251002f8a35e56f5c12dda3acccef3c0f004f42a407650c717bdcd1b356fbb1a4289ed586ae0054a28092787aa45a356c517fe9f4efede69ead500057281244eab70558353bb01ae044da04bb95cd4e005a262744990f9e193bb6c8b5d652b6759e02ad3d005ce773885e9988a5ddb3c1e37a05397bcd5eeca90065589c1592a555f265c48bb6505d43bdea15ba8b0066d95b9b63a5d1b61b5ae5e30221c3e19b29cf7300697521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad0075740087".to_string(),
//                 ),
//                 witness: Some(Vec::new()),
//                 is_coinbase: false,
//                 sequence: 4294967295,
//                 inner_redeemscript_asm: Some(
//                     "OP_PUSHDATA2 69 OP_DROP OP_PUSHBYTES_33 038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7 OP_CHECKSIGVERIFY OP_0 OP_DROP OP_DEPTH OP_0 OP_EQUAL".to_string(),
//                 ),
//             },
//             Input {
//                 txid: "9e6cdbe6be6fabca5853ea0e1230848af2268c0424cf8dcc84d6cfd5c76dda2f".to_string(),
//                 vout: 1,
//                 prevout: Prevout {
//                     scriptpubkey: "a91477937e861723eb77f160f6c7cce40dff6198820587".to_string(),
//                     scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 77937e861723eb77f160f6c7cce40dff61988205 OP_EQUAL".to_string(),
//                     scriptpubkey_type: "p2sh".to_string(),
//                     scriptpubkey_address: "3CbH2T61eXwSSvF6HFYEhwBEFEu3xvB7TV".to_string(),
//                     value: 546,
//                 },
//                 scriptsig: Some(
//                     "48304502210083937312356fe3d0113cf4877746eca86403201c89d3f5761cb1c2db67ec152702203fda8c47210b8ad9369b4d4284d900aef17f1e4a032c2dc86276c34acea71cc6014d07024ddb01434e5452505254596ca3a38f3fe0c907b81404374012bfa2c218210069e12a40d4a2218d33f208b9a0447894dc9bea31006ddfc4d5b7ceb2264a73b448af67ed3c3a6b5607006e91d6700bbe778efb4f2bcfd9afd266926eb3a6006ecc8c56c3caa932e5f2083e1803696eb1063e3b006fe066d1be6359dba98e7f00f3f45707e0bd07ad007c8a4ffa173b6bb3b66fac2d68b23867b78ebaa40087ab93d8951deb3a21ee17d5e579b9fd20bc42df008895bfc14493b6922a23b549d0e1dd98d4522d0800893fe95b34e48ef0aa69d84650a146a09a47225d00894832b6fdbef2f756cd4bb4a2e521d8e91a7364009661d2afc4c77c17bec34d696adb77f84dc4f3be0096913187e3ec0d4048b376bed6e7449cb1664299009d33d96b9e10f7e9920731a5fd996af98a9928e700a20b50f27f4e35ec0aaa9fb17e789b8dd7d551e200a727fd3c700c91c02ae7593b9c43d7c969a22dfd00ab2dbe6e68fd6e6d466c7b2f20ff903b719b908f00ac2d3e3d235f7105b4e7d2705ea5fc0390a0c7ab00b1e075520fdd44aa718c50f0b5bb6fb17c00151f00b3e279361868a86f81fc71b4440d599461dc663b00b867b20c38e7b8366400e672cd192d575f8ba69000bdf3ea9b38966f3a22e5c97bc99ea25f420b8ea400c15c8907d99c7521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5175740087".to_string(),
//                 ),
//                 scriptsig_asm: Some(
//                     "OP_PUSHBYTES_72 304502210083937312356fe3d0113cf4877746eca86403201c89d3f5761cb1c2db67ec152702203fda8c47210b8ad9369b4d4284d900aef17f1e4a032c2dc86276c34acea71cc601 OP_PUSHDATA2 4ddb01434e5452505254596ca3a38f3fe0c907b81404374012bfa2c218210069e12a40d4a2218d33f208b9a0447894dc9bea31006ddfc4d5b7ceb2264a73b448af67ed3c3a6b5607006e91d6700bbe778efb4f2bcfd9afd266926eb3a6006ecc8c56c3caa932e5f2083e1803696eb1063e3b006fe066d1be6359dba98e7f00f3f45707e0bd07ad007c8a4ffa173b6bb3b66fac2d68b23867b78ebaa40087ab93d8951deb3a21ee17d5e579b9fd20bc42df008895bfc14493b6922a23b549d0e1dd98d4522d0800893fe95b34e48ef0aa69d84650a146a09a47225d00894832b6fdbef2f756cd4bb4a2e521d8e91a7364009661d2afc4c77c17bec34d696adb77f84dc4f3be0096913187e3ec0d4048b376bed6e7449cb1664299009d33d96b9e10f7e9920731a5fd996af98a9928e700a20b50f27f4e35ec0aaa9fb17e789b8dd7d551e200a727fd3c700c91c02ae7593b9c43d7c969a22dfd00ab2dbe6e68fd6e6d466c7b2f20ff903b719b908f00ac2d3e3d235f7105b4e7d2705ea5fc0390a0c7ab00b1e075520fdd44aa718c50f0b5bb6fb17c00151f00b3e279361868a86f81fc71b4440d599461dc663b00b867b20c38e7b8366400e672cd192d575f8ba69000bdf3ea9b38966f3a22e5c97bc99ea25f420b8ea400c15c8907d99c7521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5175740087".to_string(),
//                 ),
//                 witness: Some(Vec::new()),
//                 is_coinbase: false,
//                 sequence: 4294967295,
//                 inner_redeemscript_asm: Some(
//                     "OP_PUSHDATA2 434e5452505254596ca3a38f3fe0c907b81404374012bfa2c218210069e12a40d4a2218d33f208b9a0447894dc9bea31006ddfc4d5b7ceb2264a73b448af67ed3c3a6b5607006e91d6700bbe778efb4f2bcfd9afd266926eb3a6006ecc8c56c3caa932e5f2083e1803696eb1063e3b006fe066d1be6359dba98e7f00f3f45707e0bd07ad007c8a4ffa173b6bb3b66fac2d68b23867b78ebaa40087ab93d8951deb3a21ee17d5e579b9fd20bc42df008895bfc14493b6922a23b549d0e1dd98d4522d0800893fe95b34e48ef0aa69d84650a146a09a47225d00894832b6fdbef2f756cd4bb4a2e521d8e91a7364009661d2afc4c77c17bec34d696adb77f84dc4f3be0096913187e3ec0d4048b376bed6e7449cb1664299009d33d96b9e10f7e9920731a5fd996af98a9928e700a20b50f27f4e35ec0aaa9fb17e789b8dd7d551e200a727fd3c700c91c02ae7593b9c43d7c969a22dfd00ab2dbe6e68fd6e6d466c7b2f20ff903b719b908f00ac2d3e3d235f7105b4e7d2705ea5fc0390a0c7ab00b1e075520fdd44aa718c50f0b5bb6fb17c00151f00b3e279361868a86f81fc71b4440d599461dc663b00b867b20c38e7b8366400e672cd192d575f8ba69000bdf3ea9b38966f3a22e5c97bc99ea25f420b8ea400c15c8907d99c OP_DROP OP_PUSHBYTES_33 038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7 OP_CHECKSIGVERIFY OP_PUSHNUM_1 OP_DROP OP_DEPTH OP_0 OP_EQUAL".to_string(),
//                 ),
//             },
//             Input {
//                 txid: "9e6cdbe6be6fabca5853ea0e1230848af2268c0424cf8dcc84d6cfd5c76dda2f".to_string(),
//                 vout: 2,
//                 prevout: Prevout {
//                     scriptpubkey: "a9141ca466fefa28c0f9ec66881292f77fddf481889887".to_string(),
//                     scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 1ca466fefa28c0f9ec66881292f77fddf4818898 OP_EQUAL".to_string(),
//                     scriptpubkey_type: "p2sh".to_string(),
//                     scriptpubkey_address: "34JTnniXCJsK6p1Fr1jzpaKR5nYUiELdT3".to_string(),
//                     value: 546,
//                 },
//                 scriptsig: Some(
//                     "47304402206237f1017fa1fb29aba9ccf616a050ad60e4b7ad38a5f49cc3e88fe6638a35ce022061adda29bf3f9fcca9cb1a9501d93d4d267e5648daf689fb59b5c13a173e175c014d07024ddb01434e545250525459973ee3f86277a909570cb34de61200c1bda295b54fe474ad90138626eb8f57974b59eb0003584e4160e85fa97404051a58b7bc5af6a042e800c8cafbff9d210af59fab1f2b4c58d9cd189e81e300cd49c327a5e4c8fbfcbe8394fd1dcd021a554a1700d6becd4feb44293f54966ef160cb26db6e061f3700d8c432bf8fc643e79d5a7140d8e65d04660a020600dbc48d874d48deaccf7903f9877561e20bb9fe440003d3feacd626c3a80ad4eef8f1a5d657797100ca00dfb6aa51f9955d7a77609e2c2a5d1b592c47bd9900e0e53069ab7754afc1e7774a7baed30e644514b800e4ac4e29e33553e249aab76ebb708a4a5a8bfa2d00eb8573ebc025c46c493a13131311f4c81e6cc48200eb9bbc6637aed969ce032f4680cfb874e956116c00ebb0013404622f5fecfcb386bae0a784bd68bfae00f1ef961da476631efa1e2d658f3e7e8a48eaada800f97c1bb2e33b09b13015b9d386a72982d403fbea000a23a517a0a298fff94e6296dc7e103dcf8d1b3f05824d8eb34ecd4d70d1643ed84dc32fee2c5caea4807b115043055a33fbc2078a62b0cbe6bc576f6b86804811e340fbb4879fa2483cb666479ed2e99f20028001895cd718be87efe78cafc663ca058a73cbf38240000001220f47c7e09700007521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5275740087".to_string(),
//                 ),
//                 scriptsig_asm: Some(
//                     "OP_PUSHBYTES_71 304402206237f1017fa1fb29aba9ccf616a050ad60e4b7ad38a5f49cc3e88fe6638a35ce022061adda29bf3f9fcca9cb1a9501d93d4d267e5648daf689fb59b5c13a173e175c01 OP_PUSHDATA2 4ddb01434e545250525459973ee3f86277a909570cb34de61200c1bda295b54fe474ad90138626eb8f57974b59eb0003584e4160e85fa97404051a58b7bc5af6a042e800c8cafbff9d210af59fab1f2b4c58d9cd189e81e300cd49c327a5e4c8fbfcbe8394fd1dcd021a554a1700d6becd4feb44293f54966ef160cb26db6e061f3700d8c432bf8fc643e79d5a7140d8e65d04660a020600dbc48d874d48deaccf7903f9877561e20bb9fe440003d3feacd626c3a80ad4eef8f1a5d657797100ca00dfb6aa51f9955d7a77609e2c2a5d1b592c47bd9900e0e53069ab7754afc1e7774a7baed30e644514b800e4ac4e29e33553e249aab76ebb708a4a5a8bfa2d00eb8573ebc025c46c493a13131311f4c81e6cc48200eb9bbc6637aed969ce032f4680cfb874e956116c00ebb0013404622f5fecfcb386bae0a784bd68bfae00f1ef961da476631efa1e2d658f3e7e8a48eaada800f97c1bb2e33b09b13015b9d386a72982d403fbea000a23a517a0a298fff94e6296dc7e103dcf8d1b3f05824d8eb34ecd4d70d1643ed84dc32fee2c5caea4807b115043055a33fbc2078a62b0cbe6bc576f6b86804811e340fbb4879fa2483cb666479ed2e99f20028001895cd718be87efe78cafc663ca058a73cbf38240000001220f47c7e09700007521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5275740087".to_string(),
//                 ),
//                 witness: Some(Vec::new()),
//                 is_coinbase: false,
//                 sequence: 4294967295,
//                 inner_redeemscript_asm: Some(
//                     "OP_PUSHDATA2 434e545250525459973ee3f86277a909570cb34de61200c1bda295b54fe474ad90138626eb8f57974b59eb0003584e4160e85fa97404051a58b7bc5af6a042e800c8cafbff9d210af59fab1f2b4c58d9cd189e81e300cd49c327a5e4c8fbfcbe8394fd1dcd021a554a1700d6becd4feb44293f54966ef160cb26db6e061f3700d8c432bf8fc643e79d5a7140d8e65d04660a020600dbc48d874d48deaccf7903f9877561e20bb9fe440003d3feacd626c3a80ad4eef8f1a5d657797100ca00dfb6aa51f9955d7a77609e2c2a5d1b592c47bd9900e0e53069ab7754afc1e7774a7baed30e644514b800e4ac4e29e33553e249aab76ebb708a4a5a8bfa2d00eb8573ebc025c46c493a13131311f4c81e6cc48200eb9bbc6637aed969ce032f4680cfb874e956116c00ebb0013404622f5fecfcb386bae0a784bd68bfae00f1ef961da476631efa1e2d658f3e7e8a48eaada800f97c1bb2e33b09b13015b9d386a72982d403fbea000a23a517a0a298fff94e6296dc7e103dcf8d1b3f05824d8eb34ecd4d70d1643ed84dc32fee2c5caea4807b115043055a33fbc2078a62b0cbe6bc576f6b86804811e340fbb4879fa2483cb666479ed2e99f20028001895cd718be87efe78cafc663ca058a73cbf38240000001220f47c7e0970000 OP_DROP OP_PUSHBYTES_33 038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7 OP_CHECKSIGVERIFY OP_PUSHNUM_2 OP_DROP OP_DEPTH OP_0 OP_EQUAL".to_string(),
//                 ),
//             },
//             Input {
//                 txid: "9e6cdbe6be6fabca5853ea0e1230848af2268c0424cf8dcc84d6cfd5c76dda2f".to_string(),
//                 vout: 3,
//                 prevout: Prevout {
//                     scriptpubkey: "a9149ee8d5312de0aa98c5a0946004ef34bd9db43bcf87".to_string(),
//                     scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9ee8d5312de0aa98c5a0946004ef34bd9db43bcf OP_EQUAL".to_string(),
//                     scriptpubkey_type: "p2sh".to_string(),
//                     scriptpubkey_address: "3GBFcMjNm7jaVhQ9Ufvpx6n4grqyTgJB2s".to_string(),
//                     value: 546,
//                 },
//                 scriptsig: Some(
//                     "47304402206d151e874e11da08adc049502c2507418e0457f1c749a40b445b90d7383c8a4d02200fcec760ae49dc06bbd9dfceecd9701a5c5b529ff2b8be5bfccbbfce0bc24cff014d07024ddb01434e54525052545900174876e800805c0000002e90edd001006c0000005d21dba0020068000000ba43b74004002000000174876e800806c0000002e90edd00100e40000005d21dba00200a0000000ba43b74004029000000174876e80080780000002e90edd00100a00000005d21dba00200f0000000ba43b74004007000000174876e80080180000002e90edd00100980000005d21dba0020080000000ba43b7400400a000000174876e80080560000002e90edd00100e80000005d21dba00201f8000000ba43b7400401f000000174876e80080440000002e90edd00100600000005d21dba0020138000000ba43b7400400f000000174876e800807c0000002e90edd00100040000005d21dba0020090000000ba43b74004020000000174876e80080000000002e90edd001000c0000005d21dba0020200000000ba43b74004005000000174876e80080820000002e90edd00100c80000005d21dba00200e0000000ba43b74004013000000174876e800806a0000002e90edd00100580000005d21dba0020198000000ba43b7400402d000000174876e80080460000002e90edd00100c40000005d21dba0020070000000ba43b74004008000000174876e80080220000002e90edd00100240000005d21dba00200d0000000ba47521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5375740087".to_string(),
//                 ),
//                 scriptsig_asm: Some(
//                     "OP_PUSHBYTES_71 304402206d151e874e11da08adc049502c2507418e0457f1c749a40b445b90d7383c8a4d02200fcec760ae49dc06bbd9dfceecd9701a5c5b529ff2b8be5bfccbbfce0bc24cff01 OP_PUSHDATA2 4ddb01434e54525052545900174876e800805c0000002e90edd001006c0000005d21dba0020068000000ba43b74004002000000174876e800806c0000002e90edd00100e40000005d21dba00200a0000000ba43b74004029000000174876e80080780000002e90edd00100a00000005d21dba00200f0000000ba43b74004007000000174876e80080180000002e90edd00100980000005d21dba0020080000000ba43b7400400a000000174876e80080560000002e90edd00100e80000005d21dba00201f8000000ba43b7400401f000000174876e80080440000002e90edd00100600000005d21dba0020138000000ba43b7400400f000000174876e800807c0000002e90edd00100040000005d21dba0020090000000ba43b74004020000000174876e80080000000002e90edd001000c0000005d21dba0020200000000ba43b74004005000000174876e80080820000002e90edd00100c80000005d21dba00200e0000000ba43b74004013000000174876e800806a0000002e90edd00100580000005d21dba0020198000000ba43b7400402d000000174876e80080460000002e90edd00100c40000005d21dba0020070000000ba43b74004008000000174876e80080220000002e90edd00100240000005d21dba00200d0000000ba47521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5375740087".to_string(),
//                 ),
//                 witness: Some(Vec::new()),
//                 is_coinbase: false,
//                 sequence: 4294967295,
//                 inner_redeemscript_asm: Some(
//                     "OP_PUSHDATA2  OP_DROP OP_PUSHBYTES_33 038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7 OP_CHECKSIGVERIFY OP_PUSHNUM_3 OP_DROP OP_DEPTH OP_0 OP_EQUAL".to_string(),
//                 ),
//             },
//             Input {
//                 txid: "9e6cdbe6be6fabca5853ea0e1230848af2268c0424cf8dcc84d6cfd5c76dda2f".to_string(),
//                 vout: 4,
//                 prevout: Prevout {
//                     scriptpubkey: "a914f9e272ffdd6ec40d505c59d633881312887c52c087".to_string(),
//                     scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 f9e272ffdd6ec40d505c59d633881312887c52c0 OP_EQUAL".to_string(),
//                     scriptpubkey_type: "p2sh".to_string(),
//                     scriptpubkey_address: "3QUHTH1skj5jQRzmmfgYiYT8HRxLonRPFx".to_string(),
//                     value: 29652,
//                 },
//                 scriptsig: Some(
//                     "4830450221009963fdea7364a190a2296736e166b8aadbeb1d1a6deb1d1e9a97b0764f57ecf0022062bbac1ee4ad0c4a3ef3d8bdec5579126f6d5f942e751674cbf19ab5fc7fa3b5014ce94cbe434e5452505254593b7400400b000000174876e800803a0000002e90edd00100d00000005d21dba0020178000000ba43b7400403d000000174876e80080080000002e90edd00100dc0000005d21dba00200a8000000ba43b7400402c000000174876e80080600000002e90edd00100940000005d21dba0020030000000ba43b7400402a000000174876e80080480000002e90edd00100640000005d21dba00201d8000000ba43b74004038000000174876e80080420000002e90edd001007521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5475740087".to_string(),
//                 ),
//                 scriptsig_asm: Some(
//                     "OP_PUSHBYTES_72 30450221009963fdea7364a190a2296736e166b8aadbeb1d1a6deb1d1e9a97b0764f57ecf0022062bbac1ee4ad0c4a3ef3d8bdec5579126f6d5f942e751674cbf19ab5fc7fa3b501 OP_PUSHDATA1 4cbe434e5452505254593b7400400b000000174876e800803a0000002e90edd00100d00000005d21dba0020178000000ba43b7400403d000000174876e80080080000002e90edd00100dc0000005d21dba00200a8000000ba43b7400402c000000174876e80080600000002e90edd00100940000005d21dba0020030000000ba43b7400402a000000174876e80080480000002e90edd00100640000005d21dba00201d8000000ba43b74004038000000174876e80080420000002e90edd001007521038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7ad5475740087".to_string(),
//                 ),
//                 witness: Some(Vec::new()),
//                 is_coinbase: false,
//                 sequence: 4294967295,
//                 inner_redeemscript_asm: Some(
//                     "OP_PUSHDATA1 434e5452505254593b7400400b000000174876e800803a0000002e90edd00100d00000005d21dba0020178000000ba43b7400403d000000174876e80080080000002e90edd00100dc0000005d21dba00200a8000000ba43b7400402c000000174876e80080600000002e90edd00100940000005d21dba0020030000000ba43b7400402a000000174876e80080480000002e90edd00100640000005d21dba00201d8000000ba43b74004038000000174876e80080420000002e90edd00100 OP_DROP OP_PUSHBYTES_33 038bea638bccfcc91c5ec8f63cefbd62a5b2a28e9321d46f5aef8ef083ee654bb7 OP_CHECKSIGVERIFY OP_PUSHNUM_4 OP_DROP OP_DEPTH OP_0 OP_EQUAL".to_string(),
//                 ),
//             },
//         ],
//         vout: vec![
//             Output {
//                 scriptpubkey: "6a0cce0a35e529fea5de72526b14".to_string(),
//                 scriptpubkey_asm: "OP_RETURN OP_PUSHBYTES_12 ce0a35e529fea5de72526b14".to_string(),
//                 scriptpubkey_type: "op_return".to_string(),
//                 scriptpubkey_address: None,
//                 value: 0,
//             },
//         ],
//         };

// let dummy_tx = Transaction {
//     version: 1,
//     locktime: 0,
//     vin: vec![
//         Input {
//             txid: "ae3d0489f120cab17c42fbac6525d255d12bbc9aabdf61c2516f1c198eeba498".to_string(),
//             vout: 0,
//             prevout: Prevout {
//                 scriptpubkey: "a914e7f9dc5bb29b0e5247ea69721a22a8bbb1fbf1b187".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 e7f9dc5bb29b0e5247ea69721a22a8bbb1fbf1b1 OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3NqbLVEHUFeecgdPixZw8qxpnU4QQKFebn".to_string(),
//                 value: 108152934,
//             },
//             scriptsig: Some("0047304402202031b68c29e5eb61d351e40ac4b97e5af75e071400ef88ca792c66f1faa2af72022054e79c77c83d8f71165a1df1fac9dbdc578c4ea05ac79c5d8ed7580c1c54447a01473044022011f98f3fa23f77dd8bbff0529f422d1a8890478d01c599b826651bae944bfd6d022032801d853e8edffe8199efe1cc54ee789caa427bde7fd725e9f3b6be66781c9f014c69522102f872085d71ad02072adc30a5025fd3acea57c8d8f71bf010a4681a8897966c7621020d62af7456d0a63c5b12bc37c3c1dcb8c7e49b4cfc3c375efd56db148affd401210287b8de796b2b2f45cfb18eb4930d0c880e83b71bcf90e2105bbe76c394d1edf453ae".to_string()),
//             scriptsig_asm: Some("OP_0 OP_PUSHBYTES_71 304402202031b68c29e5eb61d351e40ac4b97e5af75e071400ef88ca792c66f1faa2af72022054e79c77c83d8f71165a1df1fac9dbdc578c4ea05ac79c5d8ed7580c1c54447a01 OP_PUSHBYTES_71 3044022011f98f3fa23f77dd8bbff0529f422d1a8890478d01c599b826651bae944bfd6d022032801d853e8edffe8199efe1cc54ee789caa427bde7fd725e9f3b6be66781c9f01 OP_PUSHDATA1 522102f872085d71ad02072adc30a5025fd3acea57c8d8f71bf010a4681a8897966c7621020d62af7456d0a63c5b12bc37c3c1dcb8c7e49b4cfc3c375efd56db148affd401210287b8de796b2b2f45cfb18eb4930d0c880e83b71bcf90e2105bbe76c394d1edf453ae".to_string()),
//             witness: Some(Vec::new()),
//             is_coinbase: false,
//             sequence: 4294967295,
//             inner_redeemscript_asm: Some("OP_PUSHNUM_2 OP_PUSHBYTES_33 02f872085d71ad02072adc30a5025fd3acea57c8d8f71bf010a4681a8897966c76 OP_PUSHBYTES_33 020d62af7456d0a63c5b12bc37c3c1dcb8c7e49b4cfc3c375efd56db148affd401 OP_PUSHBYTES_33 0287b8de796b2b2f45cfb18eb4930d0c880e83b71bcf90e2105bbe76c394d1edf4 OP_PUSHNUM_3 OP_CHECKMULTISIG".to_string()),
//         },
//     ],
//     vout: vec![
// Output {
//     scriptpubkey: "0014f63d3a0e0f77da2cf7de0f14b3122923e678e8b8".to_string(),
//     scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 f63d3a0e0f77da2cf7de0f14b3122923e678e8b8".to_string(),
//     scriptpubkey_type: "v0_p2wpkh".to_string(),
//     scriptpubkey_address: Some("bc1q7c7n5rs0wldzea77pu2txy3fy0n8369c4q06pv".to_string()),
//     value: 132152,
// },
// Output {
//     scriptpubkey: "00148c7419726ab1ed7cdcd17311ef19c2cf2af95317".to_string(),
//     scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 8c7419726ab1ed7cdcd17311ef19c2cf2af95317".to_string(),
//     scriptpubkey_type: "v0_p2wpkh".to_string(),
//     scriptpubkey_address: Some("bc1q336pjun2k8khehx3wvg77xwzeu40j5chsrzqja".to_string()),
//     value: 150539,
// },
// Output {
//     scriptpubkey: "512036fdf15226dae6bb154169b55bfa50a9a328c450c13f33da982b1aa402efe07f".to_string(),
//     scriptpubkey_asm: "OP_PUSHNUM_1 OP_PUSHBYTES_32 36fdf15226dae6bb154169b55bfa50a9a328c450c13f33da982b1aa402efe07f".to_string(),
//     scriptpubkey_type: "v1_p2tr".to_string(),
//     scriptpubkey_address: Some("bc1pxm7lz53xmtntk92pdx64h7js4x3j33zscyln8k5c9vd2gqh0uplsugy7s4".to_string()),
//     value: 687925,
// },
// Output {
//     scriptpubkey: "76a91437b1e9b2bd1fe856ff1d521e798e09adf0551fd188ac".to_string(),
//     scriptpubkey_asm: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 37b1e9b2bd1fe856ff1d521e798e09adf0551fd1 OP_EQUALVERIFY OP_CHECKSIG".to_string(),
//     scriptpubkey_type: "p2pkh".to_string(),
//     scriptpubkey_address: Some("165VJ9xsFoKJVZvFG8y4drMjiDaDsX8gzo".to_string()),
//     value: 56733618,
// },
// Output {
//     scriptpubkey: "5120a6cd798c72d61877bb909dadcb885b9eca18e1b2a4c95e1026b660f4bd69999f".to_string(),
//     scriptpubkey_asm: "OP_PUSHNUM_1 OP_PUSHBYTES_32 a6cd798c72d61877bb909dadcb885b9eca18e1b2a4c95e1026b660f4bd69999f".to_string(),
//     scriptpubkey_type: "v1_p2tr".to_string(),
//     scriptpubkey_address: Some("bc1p5mxhnrrj6cv80wusnkkuhzzmnm9p3cdj5ny4uypxkes0f0tfnx0sv86a49".to_string()),
//     value: 100000,
// },
// Output {
//     scriptpubkey: "512069f372f0ee43e870f1910ef4316f939b8ffc95891757d389d3c7413280eb2e1c".to_string(),
//     scriptpubkey_asm: "OP_PUSHNUM_1 OP_PUSHBYTES_32 69f372f0ee43e870f1910ef4316f939b8ffc95891757d389d3c7413280eb2e1c".to_string(),
//     scriptpubkey_type: "v1_p2tr".to_string(),
//     scriptpubkey_address: Some("bc1pd8eh9u8wg058puv3pm6rzmunnw8le9vfzata8zwncaqn9q8t9cwqayefda".to_string()),
//     value: 1970000,
// },
// Output {
//     scriptpubkey: "0014f86d4b821d248c2a9aa40d69b0094d8d8c28ce7c".to_string(),
//     scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 f86d4b821d248c2a9aa40d69b0094d8d8c28ce7c".to_string(),
//     scriptpubkey_type: "v0_p2wpkh".to_string(),
//     scriptpubkey_address: Some(
//         "bc1qlpk5hqsayjxz4x4yp45mqz2d3kxz3nnuxrluq2".to_string(),
//     ),
//     value: 100000,
// },
// Output {
//     scriptpubkey: "5120f47e6840914c5122127d1e46ab814eae2dfd3e4f0c0a056bd4cd74b9f139d69c".to_string(),
//     scriptpubkey_asm: "OP_PUSHNUM_1 OP_PUSHBYTES_32 f47e6840914c5122127d1e46ab814eae2dfd3e4f0c0a056bd4cd74b9f139d69c".to_string(),
//     scriptpubkey_type: "v1_p2tr".to_string(),
//     scriptpubkey_address: Some(
//         "bc1p73lxssy3f3gjyynarer2hq2w4ckl60j0ps9q2675e46tnufe66wqy30ewz".to_string(),
//     ),
//     value: 917626,
// },
// Output {
//     scriptpubkey: "5120963c530d15178e9cdf67c624f2eb673c6fe264a1fca7bfb8f937579f92a0572f".to_string(),
//     scriptpubkey_asm: "OP_PUSHNUM_1 OP_PUSHBYTES_32 963c530d15178e9cdf67c624f2eb673c6fe264a1fca7bfb8f937579f92a0572f".to_string(),
//     scriptpubkey_type: "v1_p2tr".to_string(),
//     scriptpubkey_address: Some("bc1pjc79xrg4z78fehm8ccj096m883h7ye9pljnmlw8exately4q2uhs9s0uca".to_string()),
//     value: 182484,
// },
// Output {
//     scriptpubkey: "0020e5c7c00d174631d2d1e365d6347b016fb87b6a0c08902d8e443989cb771fa7ec".to_string(),
//     scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 e5c7c00d174631d2d1e365d6347b016fb87b6a0c08902d8e443989cb771fa7ec".to_string(),
//     scriptpubkey_type: "v0_p2wsh".to_string(),
//     scriptpubkey_address: Some("bc1quhruqrghgcca950rvhtrg7cpd7u8k6svpzgzmrjy8xyukacl5lkq0r8l2d".to_string()),
//     value: 47131590,
// },],
// };

// P2SH-P2WPKH

// let dummy_tx = Transaction {
//     version: 2,
//     locktime: 0,
//     vin: vec![
//         Input {
//             txid: "6d57c863b52f812a74a742ca185f3672d30fab0941989c7f3ecaa6b9c69ef65f".to_string(),
//             vout: 1,
//             prevout: Prevout {
//                 scriptpubkey: "a914d84e569b6e08184a576417226b27ab0b01c0303787".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 d84e569b6e08184a576417226b27ab0b01c03037 OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3MQjj28SJ5n4h9XXTzudZS2Sxm97pAZkuV".to_string(),
//                 value: 3592047,
//             },
//             scriptsig: Some("160014835f3378e186cda9ef674042b2272f333e7a7f4b".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_22 0014835f3378e186cda9ef674042b2272f333e7a7f4b".to_string()),
//             witness: Some(vec![
//                 "30440220207dab70062734c729b35024d5c61a1b90dd95aeb740172fe4350960a8ec48c202205002b6cc63afb8a05431994140592b675737db71c07e093f7b5ada6363679cb701".to_string(),
//                 "0394bd74ea55eb0c8acf11ea27da5a46fc6bc795e51e72f79c24e5ab9cf53ba88b".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_20 835f3378e186cda9ef674042b2272f333e7a7f4b".to_string()),
//         }
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "0014db562202f7393129acba87250f17312ad39a52b6".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 db562202f7393129acba87250f17312ad39a52b6".to_string(),
//             scriptpubkey_type: "v0_p2wpkh".to_string(),
//             scriptpubkey_address: Some("bc1qmdtzyqhh8ycjnt96sujs79e39tfe554k7rz7p2".to_string()),
//             value: 3589558,
//         }
//     ],
// };

// let dummy_tx = Transaction {
//     version: 2,
//     locktime: 0,
//     vin: vec![
//         Input {
//             // First input
//             txid: "bd108bdf1c25ab0b0095d4a0cc24e1a46160bc446d62e50528b69387af70e5ca".to_string(),
//             vout: 2,
//             prevout: Prevout {
//                 scriptpubkey: "a914b321cc76fb438182ec9726943f8a46bbd02a8b8287".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 b321cc76fb438182ec9726943f8a46bbd02a8b82 OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3J2BNFn3UDT6qb4MX7gj2wH1kwZZSG5aj4".to_string(),
//                 value: 17959,
//             },
//             scriptsig: Some("160014731ae3552a43d884678076179e7ed53669d15321".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_22 0014731ae3552a43d884678076179e7ed53669d15321".to_string()),
//             witness: Some(vec![
//                 "3045022100bfd9deee2b9448e67bacf189714b203bb007b57e1b3be67967ef7c5314390c540220520c455c611349b6bb74b7378aa39680391e49c3b61fb7de10aa6853ece5825901".to_string(),
//                 "03545cc84c0e290ceaef9f025b65e7f2c2987c30923d8169c5fea8644ad8f7b28e".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_20 731ae3552a43d884678076179e7ed53669d15321".to_string()),
//         },
//         // Second input (similar structure)
//         Input {
//             txid: "7cfe72520f916f5e46ecfbc0b732efdd71af307ff16bd2e2239150f008e08c61".to_string(),
//             vout: 2,
//             prevout: Prevout {
//                 scriptpubkey: "a914b321cc76fb438182ec9726943f8a46bbd02a8b8287".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 b321cc76fb438182ec9726943f8a46bbd02a8b82 OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3J2BNFn3UDT6qb4MX7gj2wH1kwZZSG5aj4".to_string(),
//                 value: 69655,
//             },
//             scriptsig: Some("160014731ae3552a43d884678076179e7ed53669d15321".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_22 0014731ae3552a43d884678076179e7ed53669d15321".to_string()),
//             witness: Some(vec![
//                 "304402200d857ad277886fc638d5550f58125b3a3708ed7d6bf5fe5d6be4e95da4f63a2d02205fb6ff74e551dc710e8310e99cd2106513b70953ce44d85d287bc51e63437e0a01".to_string(),
//                 "03545cc84c0e290ceaef9f025b65e7f2c2987c30923d8169c5fea8644ad8f7b28e".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_20 731ae3552a43d884678076179e7ed53669d15321".to_string()),
//         },
//     ],
//     vout: vec![
//         Output {
//             // First output
//             scriptpubkey: "a91497a37a77743394091c921d3f5724a9ba08d6683987".to_string(),
//             scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 97a37a77743394091c921d3f5724a9ba08d66839 OP_EQUAL".to_string(),
//             scriptpubkey_type: "p2sh".to_string(),
//             scriptpubkey_address: Some("3FWooBpwv9nvAhjvWUKkQRdomAVBYguGzo".to_string()),
//             value: 84239,
//         },
//         // Second output (similar structure)
//     ],
// };

// P2SH-P2WSH

// let dummy_tx: Transaction = Transaction {
//     version: 1,
//     locktime: 0,
//     vin: vec![
//         Input {
//             // First input
//             txid: "1ee89ed98f4eb69e7d8a3b119dde2b1ab5cec9efc08180e30b703aaf935b7eff".to_string(),
//             vout: 0,
//             prevout: Prevout {
//                 // Previous output script pubkey
//                 scriptpubkey: "a914801433bd07f7815c022590e650d2b5dcd446188f87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 801433bd07f7815c022590e650d2b5dcd446188f OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3DNEcmJyg6VPHR7TdFFmyD2LZoDNnLbtjH".to_string(),
//                 value: 29487
//             },
//             scriptsig: Some("22002088f1113338f508ef10d34df6e92de68210947f8e65a967da2ff1418207e1c3e3".to_string()), // ScriptSig data
//             scriptsig_asm: Some("OP_PUSHBYTES_34 002088f1113338f508ef10d34df6e92de68210947f8e65a967da2ff1418207e1c3e3".to_string()), // ScriptSig ASM
//             witness: Some(vec![
//                 "".to_string(),
//                 "304402204560f43175abd3a471bacfa58f0acb6f713097f16c2afed2459841b407874b53022055ca039e15055cce7d5a661395a9c1a054e99228eeff41a80165a954d1ae91ee01".to_string(),
//                 "304402202cb77cad6898ab2da68282c8c16e0f1be91e2d2664c96769aa1b553bc6f55c4c02203c31cce2a40e4bf3c055f9f7fbeb54fc217f9d6853580272ef637e3d994cd3ae01".to_string(),
//                 "5221036b59711184e6a5f10f3692b0a213965e7756f116d2687f5af735f75c670d8dc521033f67b4653f6f60081c649081c5626c1d4bf03f6b9f092a713558d29cdbf649872102fd985948136c8e1395ffff58e3aec4e2b8e8296f9d89eec77f0025149e7308aa53ae".to_string()
//             ]), // Witness data
//             is_coinbase: false,
//             sequence: 4294967293, // Sequence number
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_32 88f1113338f508ef10d34df6e92de68210947f8e65a967da2ff1418207e1c3e3".to_string()), // Redeem script ASM
//         },
//         // Second input (similar structure)
//         Input {
//             // Second input
//             txid: "ba131f276fd8f979fdd0600ccbd9efbea8b0dbe1b0fef6a69f4a43579507c115".to_string(),
//             vout: 1,
//             prevout: Prevout {
//                 // Previous output script pubkey
//                 scriptpubkey: "a914801433bd07f7815c022590e650d2b5dcd446188f87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 801433bd07f7815c022590e650d2b5dcd446188f OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3DNEcmJyg6VPHR7TdFFmyD2LZoDNnLbtjH".to_string(),
//                 value: 6966126
//             },
//             scriptsig: Some("22002088f1113338f508ef10d34df6e92de68210947f8e65a967da2ff1418207e1c3e3".to_string()), // ScriptSig data
//             scriptsig_asm: Some("OP_PUSHBYTES_34 002088f1113338f508ef10d34df6e92de68210947f8e65a967da2ff1418207e1c3e3".to_string()), // ScriptSig ASM
//             witness: Some(vec![
//                 "".to_string(),
//                 "3045022100f2a7f884e86f864ce629502224ed193808593227c996b41099231f2106282c0402204b958b99b111865ce84565fa243c2c2411b727a6526770aaca3858416287e5cb01".to_string(),
//                 "304402203e01e751ebfc34bce750fd5b4133e3f6669d103c7dfb75d9f72fb0007f68f34b0220258ce78124021c4ce2189977781b8c49502a6c1d79c2f1b79861d434113569f901".to_string(),
//                 "5221036b59711184e6a5f10f3692b0a213965e7756f116d2687f5af735f75c670d8dc521033f67b4653f6f60081c649081c5626c1d4bf03f6b9f092a713558d29cdbf649872102fd985948136c8e1395ffff58e3aec4e2b8e8296f9d89eec77f0025149e7308aa53ae".to_string()
//             ]), // Witness data
//             is_coinbase: false,
//             sequence: 4294967293, // Sequence number
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_32 88f1113338f508ef10d34df6e92de68210947f8e65a967da2ff1418207e1c3e3".to_string()), // Redeem script ASM
//         }
//     ],
//     vout: vec![
//         Output {
//             // First output
//             scriptpubkey: "a914801433bd07f7815c022590e650d2b5dcd446188f87".to_string(),
//             scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 801433bd07f7815c022590e650d2b5dcd446188f OP_EQUAL".to_string(),
//             scriptpubkey_type: "p2sh".to_string(),
//             scriptpubkey_address: Some("3DNEcmJyg6VPHR7TdFFmyD2LZoDNnLbtjH".to_string()),
//             value: 7759 // Output value
//         },
//         // Second output (similar structure)
//         Output {
//             // Second output
//             scriptpubkey: "76a91452086cc8a5e28b2eec744109ef42baa645bbc90d88ac".to_string(),
//             scriptpubkey_asm: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 52086cc8a5e28b2eec744109ef42baa645bbc90d OP_EQUALVERIFY OP_CHECKSIG".to_string(),
//             scriptpubkey_type: "p2pkh".to_string(),
//             scriptpubkey_address: Some("18UkW764x1FJLjV7GkPMXkix4sshkBaqc9".to_string()),
//             value: 6980000 // Output value
//         }
//     ]
// };

// let dummy_tx: Transaction = Transaction {
//     version: 2,
//     locktime: 834637,
//     vin: vec![
//         Input {
//             // First input
//             txid: "23b7848ccf03eab961339cfbb13729c0bbcb7ac6f2366c2dcad1e7992c582a37".to_string(),
//             vout: 1,
//             prevout: Prevout {
//                 scriptpubkey: "a914299081f891684dd285fa9d92d5077543f0559e5287".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 299081f891684dd285fa9d92d5077543f0559e52 OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "35UnjynA4TivdX5W2JFtVPj51TFD6Scisg".to_string(),
//                 value: 5774273,
//             },
//             scriptsig: Some("220020e585f513eb7d0e4616179ef7790c1300f49d5c89d289f84a72d58970b975d1c6".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_34 0020e585f513eb7d0e4616179ef7790c1300f49d5c89d289f84a72d58970b975d1c6".to_string()),
//             witness: Some(vec![
//                 "3044022036adbcc8378c7e3a6dbbbc18d288d0c5b40018ee3fb986baca36155215d9583302203c606267706ae77039a26c782cbe50102b8afbb31bc56c6651282ded830a73eb01".to_string(),
//                 "30440220330baf8e4261a258e45bfef1c6929ea4e5a55fff19de222efaff1ec364e935a302204db3f9bcc9473d609726153976c9c6ef50417cc01ef57398e09257a09da58d7a01".to_string(),
//                 "2103b9f6a50801afa308c79538956fd8bcd7166c0498800ff3536844f5b2a1645d13ad2102205b7b198421c55dd193519adac8e1b23067da08679084310d5a0e281d68aadeac73640380ca00b268".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_32 e585f513eb7d0e4616179ef7790c1300f49d5c89d289f84a72d58970b975d1c6".to_string()),
//         },
//         Input {
//             // Second input
//             txid: "b414892331429bbe8d53be5ed82d24185c27b504c03d5f634759f2522faae443".to_string(),
//             vout: 1,
//             prevout: Prevout {
//                 scriptpubkey: "a91436107ea05ff672c804b156d052c45989754b5b8a87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 36107ea05ff672c804b156d052c45989754b5b8a OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "36ctAyD1DSpvzc9TDFzg4cBrJdpo2YGoVg".to_string(),
//                 value: 4449692,
//             },
//             scriptsig: Some("22002091db211d867a59e3af65d855d1c43efc540c51258d023fd15872c9c95ae80153".to_string()),
//             scriptsig_asm: Some("OP_PUSHBYTES_34 002091db211d867a59e3af65d855d1c43efc540c51258d023fd15872c9c95ae80153".to_string()),
//             witness: Some(vec![
//                 "304402206ee371d9e236b7a9ed783188bcfdf0580a24b7a088cf5cc4a87f80d33bece0a202201605b919d99e48b63b0a5972857c02d2e36a25c18326b698de07815bdb6de57a01".to_string(),
//                 "304402200d2b8db36d78719b2806a2af915a85be6d01263eac144a9fc6d37b75039c7adf02202ade193044d8e09afd497aa617f482eec95f0ef9affd29cc258b0b1b5047d3c801".to_string(),
//                 "21033f696e039a47d48681c0cb909b47d709d331f1a0115561878cfe06676630f521ad21030b81b7d5ee344cdfc520b642385280caef00b23791c6f389806898d0ae72bbc7ac73640380ca00b268".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 4294967293,
//             inner_redeemscript_asm: Some("OP_0 OP_PUSHBYTES_32 91db211d867a59e3af65d855d1c43efc540c51258d023fd15872c9c95ae80153".to_string()),
//         }
//     ],
//     vout: vec![
//         Output {
//             // First output
//             scriptpubkey: "001445767e823885b309e5225c6cd51e6d25a91d3e92".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_20 45767e823885b309e5225c6cd51e6d25a91d3e92".to_string(),
//             scriptpubkey_type: "v0_p2wpkh".to_string(),
//             scriptpubkey_address: Some("bc1qg4m8aq3cskesnefzt3kd28ndyk53605jmz7xc2".to_string()),
//             value: 5000000,
//         },
//         Output {
//             // Second output
//             scriptpubkey: "a914feda0207f9572be49799f3d098f367d2da557d1b87".to_string(),
//             scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 feda0207f9572be49799f3d098f367d2da557d1b OP_EQUAL".to_string(),
//             scriptpubkey_type: "p2sh".to_string(),
//             scriptpubkey_address: Some("3QvYij2qKW4KQvfS5ycefTbKFY3C6e3poa".to_string()),
//             value: 5215515,
//         },
//     ]
// };

// let dummy_tx = Transaction {
//     version: 2,
//     locktime: 833158,
//     vin: vec![
//         Input {
//             txid: "e5d10a9e6956c9e8d79594f5acb20223f51b9cf4a1ed78c9517e4184ca68a9b3".to_string(),
//             vout: 184,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 16511,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "3044022052e054510e0d6db8c2d1195b5be113dfdf4d8d99c9e264b4dfd4a101d6d532fc022050b618e2e5f347ec6ec4c005bf589dcd8c4b04c812efec29225dd3a05813832001".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "5af87b760cad8ed080fc6cf2ba70040e31c89af5b746a968d4e783806a3ebf49".to_string(),
//             vout: 47,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 35920,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "30440220557b674e096640c7361e2ea9028dc56fb906f281203e01029370aefc485e36b7022015dcc281395064fec31588f4c963a01c273ba528380f53fcc6b421d4a35191f201".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "65f2cac5fce95ac6d8566e21533e6382fbc5425b2fb878f614d39812e45af804".to_string(),
//             vout: 391,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 35511,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "30440220086c2c1e5a406fa92ab5d75afc76b3fdea9f40395f1be929495d6f5def79b5b1022071b9597c42305751ba8d0e10da3d986e9adee40b9a4b7ae32551dc833fd2380001".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "7f540c947af7a13d0e1ae01b43722467041dc85d8f8cede9b3d863778575f7ab".to_string(),
//             vout: 94,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 52807,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "304402203cf6e30e4f16d6aea678e5e601eec1b574b5e8831e571383e9bb6fafabccdc9a022070e0054c25fb4228e646b2fb1b9e846b594ce507b25aaa9422c4aa7c38a8c0c201".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "3e13dbb523dd719f24acf3cb7096b1d4faf2af21b63159f886b436ebc03d7c94".to_string(),
//             vout: 109,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 29503,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "3044022037075fe91bc846075bbbb4c0dfde3078e9efe3e09c1e4f6fcbe47ae972051dd102204dd7491fa46ce222fa1bb78cb8de7a3442778e33e24626aa3e8517d76ff7cd3101".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "15b802f54d14e13bc601d425688a26cb9692eed925f4bbe58a756787e7281195".to_string(),
//             vout: 81,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 27147,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "304402204971480e51b2f6cac9b04ff7db4595af38dc3a6e0becca4778e3091725d79000022031ca7b26f93b9b3399d8a30f15bfbfa92899ad0d2e93aaf49c3890b94dc5c38c01".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "ab6e5f10908b40c99afaa5a45a1d4b2f0fc48810c8c58c1620038537cf17a681".to_string(),
//             vout: 117,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 44241,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "3044022041405923b9e2a65514648cf96502771199d87c90c4221efb5f8d9ea81022a33502205c3662bf481a72e132eaa97bc9cf7c690e955b95fef8ab127fb55d9dbd4b257a01".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "bb5226c1c3c7ca22d6c7ce46011e060eb56929d09d257eb3a0b3198e8e88ea02".to_string(),
//             vout: 104,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 157783,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "304402206979855a0c716679182dcd4535250e62add1da39cfbf69a757f91379cd3728a7022021b99e1aa7b7e4a9481ef7a4b7e6d220362b921d4706e0e08d57c738e85db24201".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "bb5226c1c3c7ca22d6c7ce46011e060eb56929d09d257eb3a0b3198e8e88ea02".to_string(),
//             vout: 161,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 47244,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "304402204b60627e70a35673868cb9c8ec9163a61bbb2361e555a7aef25d64b03fee338002204f98c3fb752aadaa1b68e9892b3572b59a266806ab456505bfd04b1ac659558801".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//         Input {
//             txid: "482b9b787e3928e72654957be82c2e4eced9f40288703644f880918697e31596".to_string(),
//             vout: 193,
//             prevout: Prevout {
//                 scriptpubkey: "a9149bd64e211265ab1253de7d62f36365c9e0cf857c87".to_string(),
//                 scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 9bd64e211265ab1253de7d62f36365c9e0cf857c OP_EQUAL".to_string(),
//                 scriptpubkey_type: "p2sh".to_string(),
//                 scriptpubkey_address: "3Fu1PTpfSJFDLEAqGEW46NVbgoWR7ojAyo".to_string(),
//                 value: 35004,
//             },
//             scriptsig: Some(
//                 "22002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             scriptsig_asm: Some(
//                 "OP_PUSHBYTES_34 002096e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//             witness: Some(vec!
//                 [
//                     "".to_string(),
//                     "304402205d05aabfbd4efb0d505d6e59cd05b5011a3c844057046d314e5c6a8895fea2bd02205e101abb5cb5d7d47274d6a1362e9b0b44491801e24252343e58cbab2ff76d4801".to_string(),
//                     "2102eddf2257db044b1ce1dc9b1b4a78c304106962322abcc761ad7c00feed482ffaad21038aade0256f0b09b295318a9e7dd9c05ae6c50253bb0dd4feb6749e64736ee844ac73640380ca00b268".to_string(),
//                 ],
//             ),
//             is_coinbase: false,
//             sequence: 51840,
//             inner_redeemscript_asm: Some(
//                 "OP_0 OP_PUSHBYTES_32 96e2d092c0427b023c04d0f4e8c131204e9d8dd82cb6cb090d6f58c3d9b85960".to_string(),
//             ),
//         },
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "a91414a7c89e76b8d39ccdc4d31c08febfb5afdd5fd187".to_string(),
//             scriptpubkey_asm: "OP_HASH160 OP_PUSHBYTES_20 14a7c89e76b8d39ccdc4d31c08febfb5afdd5fd1 OP_EQUAL".to_string(),
//             scriptpubkey_type: "p2sh".to_string(),
//             scriptpubkey_address: Some(
//                 "33aESCCpyAkuU4CCdGi1NkbgkokLMY2SKF".to_string(),
//             ),
//             value: 468659,
//         },
//     ],
// };
