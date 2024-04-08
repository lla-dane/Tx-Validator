use std::vec;

use hex;

use crate::validation_checks::hash160;
use crate::validation_checks::op_checkmultisig;
use crate::validation_checks::op_checksig;

use crate::{error::Result, transaction::Transaction};

use super::single_sha256;

pub fn input_verification_p2wsh(tx_input_index: usize, tx: Transaction) -> Result<bool> {
    let witness = match tx.vin[tx_input_index].witness.clone() {
        Some(value) => value,
        None => Vec::new(),
    };

    Ok(script_execution_p2wsh(witness, tx, tx_input_index)?)
}

fn script_execution_p2wsh(
    witness: Vec<String>,
    tx: Transaction,
    tx_input_index: usize,
) -> Result<bool> {
    if witness.len() == 0 {
        return Ok(false);
    }

    let input_type = "P2WSH";
    let mut script_result = false;

    let mut stack: Vec<Vec<u8>> = Vec::new();

    // PUSH SIGNATURES

    for index in 0..witness.len() - 1 {
        stack.push(hex::decode(&witness[index])?);
    }

    // EXECUTING WITNESS SCRIPT

    let witness_script_bytes = hex::decode(&witness.last().cloned().expect("SCRIPT MISSING"))?;

    let scriptpubkey_asm = tx.vin[tx_input_index].prevout.scriptpubkey_asm.clone();
    let scriptpubkey_asm_slices: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();
    let witness_program = scriptpubkey_asm_slices
        .last()
        .cloned()
        .unwrap_or("witness program: missing");
    let witness_program_bytes = hex::decode(&witness_program)?;

    let witnness_script_hash = single_sha256(&witness_script_bytes);

    if witnness_script_hash != witness_program_bytes {
        // println!("SCRIPTPUBKEY: FAILED");

        return Ok(false);
    }

    // println!("SCRIPTPUBKEY: SUCCESSFULL");

    let mut index = 0;

    while index < witness_script_bytes.len() {
        let opcode = witness_script_bytes[index];
        index += 1;

        match opcode {
            _ if opcode <= 96 && opcode >= 81 => {
                stack.push(vec![opcode - 80]);
            }

            _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                // OP_PUSHBYTES_33
                if index + opcode as usize <= witness_script_bytes.len() {
                    let bytes = witness_script_bytes[index..index + opcode as usize].to_vec();
                    stack.push(bytes);
                    index += opcode as usize;
                }
            }

            174 => {
                // OP_CHECKMULTISIG
                let result_multisig =
                    op_checkmultisig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                if result_multisig == true {
                    script_result = true;
                    stack.push(vec![1u8]);
                } else {
                    stack.push(vec![0u8])
                }
            }

            173 => {
                // OP_CHECKSIGVERIFY
                let result_singlesig =
                    op_checksig(&mut stack, tx.clone(), tx_input_index, input_type)?;

                if result_singlesig == true {
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

                let sig_length = stack[stack.len() - 2].len();

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

            169 => {
                // OP_HASH160
                let top = stack.pop().unwrap_or(vec![254u8]);
                stack.push(hash160(&top));
            }

            135 => {
                // OP_EQUAL
                let a = stack.pop().unwrap_or(vec![254u8]);
                let b = stack.pop().unwrap_or(vec![254u8]);

                if a == b {
                    stack.push(vec![1u8]);
                } else {
                    stack.push(vec![0u8]);
                }
            }

            99 => {
                // OP_NOTIF
                let top_stack_value = stack.pop().unwrap_or(vec![254u8]);
                let mut path = "else";
                let mut else_appeared = 0;
                if top_stack_value == vec![1u8] {
                    path = "if";
                }

                loop {
                    let opcode = witness_script_bytes[index];
                    index += 1;

                    match opcode {
                        117 => {
                            //  OP_DROP
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                stack.pop();
                            }
                        }

                        118 => {
                            // OP_DUP
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.last().cloned().unwrap_or(vec![254u8]);
                                stack.push(top);
                            }
                            // println!("{:?}", stack);
                        }

                        169 => {
                            //OP_HASH160
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.pop().unwrap_or(vec![254u8]);
                                stack.push(hash160(&top));
                            }
                        }

                        _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                            // OP_PUSHBYTES_33

                            if index + opcode as usize <= witness_script_bytes.len() {
                                let bytes =
                                    witness_script_bytes[index..index + opcode as usize].to_vec();

                                if (path == "if" && else_appeared == 0)
                                    || (path == "else" && else_appeared == 1)
                                {
                                    stack.push(bytes);
                                }
                                index += opcode as usize;
                            }
                            // println!("{:?}", stack);
                        }

                        136 => {
                            // OP_EQUALVERIFY
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }

                                // OP_VERIFY

                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        135 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        105 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        103 => {
                            // OP_ELSE
                            else_appeared = 1;
                        }

                        173 => {
                            // OP_CHECKSIGVERIFY
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let result_singlesig = op_checksig(
                                    &mut stack,
                                    tx.clone(),
                                    tx_input_index,
                                    input_type,
                                )?;

                                if result_singlesig == true {
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
                        }

                        172 => {
                            // OP_CHECKSIG

                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let sig_length = stack[stack.len() - 1].len();

                                if sig_length <= 75 && sig_length >= 70 {
                                    script_result = op_checksig(
                                        &mut stack,
                                        tx.clone(),
                                        tx_input_index,
                                        input_type,
                                    )?;

                                    if script_result == true {
                                        stack.push(vec![1u8]);
                                    } else {
                                        stack.push(vec![0u8])
                                    }
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        130 => {
                            // OP_SIZE
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let last_len =
                                    stack.last().cloned().unwrap_or(vec![254u8]).len() as u8;
                                stack.push(vec![last_len]);
                            }
                        }

                        104 => {
                            // println!("OP_IF: SUCCESSFULL");
                            break;
                        }

                        _ => continue,
                    }
                }
            }

            100 => {
                // OP_NOTIF
                let top_stack_value = stack.pop().unwrap_or(vec![254u8]);
                let mut path = "else";
                let mut else_appeared = 0;
                if top_stack_value == vec![0u8] {
                    path = "if";
                }

                loop {
                    let opcode = witness_script_bytes[index];
                    index += 1;

                    match opcode {
                        117 => {
                            //  OP_DROP
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                stack.pop();
                            }
                        }

                        118 => {
                            // OP_DUP
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.last().cloned().unwrap_or(vec![254u8]);
                                stack.push(top);
                            }
                            // println!("{:?}", stack);
                        }

                        169 => {
                            //OP_HASH160
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top = stack.pop().unwrap_or(vec![254u8]);
                                stack.push(hash160(&top));
                            }
                        }

                        _ if opcode <= 75 as u8 && opcode >= 1 as u8 => {
                            // OP_PUSHBYTES_33

                            if index + opcode as usize <= witness_script_bytes.len() {
                                let bytes =
                                    witness_script_bytes[index..index + opcode as usize].to_vec();

                                if (path == "if" && else_appeared == 0)
                                    || (path == "else" && else_appeared == 1)
                                {
                                    stack.push(bytes);
                                }
                                index += opcode as usize;
                            }
                            // println!("{:?}", stack);
                        }

                        136 => {
                            // OP_EQUALVERIFY
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }

                                // OP_VERIFY

                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        135 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let a = stack.pop().unwrap_or(vec![254u8]);
                                let b = stack.pop().unwrap_or(vec![254u8]);

                                if a == b {
                                    stack.push(vec![1u8]);
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        105 => {
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let top_verify = stack.pop().unwrap();
                                if top_verify != vec![1u8] {
                                    return Ok(false);
                                }
                            }
                        }

                        103 => {
                            // OP_ELSE
                            else_appeared = 1;
                        }

                        173 => {
                            // OP_CHECKSIGVERIFY
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let result_singlesig = op_checksig(
                                    &mut stack,
                                    tx.clone(),
                                    tx_input_index,
                                    input_type,
                                )?;

                                if result_singlesig == true {
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
                        }

                        172 => {
                            // OP_CHECKSIG

                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let sig_length = stack[stack.len() - 1].len();

                                if sig_length <= 75 && sig_length >= 70 {
                                    script_result = op_checksig(
                                        &mut stack,
                                        tx.clone(),
                                        tx_input_index,
                                        input_type,
                                    )?;

                                    if script_result == true {
                                        stack.push(vec![1u8]);
                                    } else {
                                        stack.push(vec![0u8])
                                    }
                                } else {
                                    stack.push(vec![0u8]);
                                }
                            }
                        }

                        130 => {
                            // OP_SIZE
                            if (path == "if" && else_appeared == 0)
                                || (path == "else" && else_appeared == 1)
                            {
                                let last_len =
                                    stack.last().cloned().unwrap_or(vec![254u8]).len() as u8;
                                stack.push(vec![last_len]);
                            }
                        }

                        104 => {
                            // println!("OP_NOTIF: SUCCESSFULL");
                            break;
                        }

                        _ => continue,
                    }
                }
            }

            _ => continue,
        }
    }

    Ok(script_result)
}

// #[cfg(test)]
// mod test {
//     use std::fs;

//     use walkdir::WalkDir;

//     use super::*;

//     #[test]
//     fn test_script_execution_p2wsh() -> Result<()> {
//         let mut s_count = 0;
//         let mut f_count = 0;
//         let mempool_dir = "./mempool";
//         for entry in WalkDir::new(mempool_dir).into_iter().filter_map(|e| e.ok()) {
//             let path = entry.path();
//             if path.is_file() {
//                 match fs::read_to_string(path) {
//                     Ok(contents) => {
//                         match serde_json::from_str::<Transaction>(&contents) {
//                             Ok(transaction) => {
//                                 // Check if all inputs' prevout scriptpubkey_type are .p2sh
//                                 let all_p2sh = transaction.vin.iter().all(|input| {
//                                     input.prevout.scriptpubkey_type == "v0_p2wsh".to_string()
//                                 });
//                                 if all_p2sh {
//                                     let result = script_execution_p2wsh(
//                                         transaction.vin[0].witness.clone().unwrap(),
//                                         transaction,
//                                         0,
//                                     )?;

//                                     if result == true {
//                                         s_count += 1;
//                                     } else {
//                                         f_count += 1;
//                                     }

//                                     // println!("\n\n");
//                                 }
//                             }
//                             Err(e) => {
//                                 // println!("Failed to parse JSON: {}", e);
//                             }
//                         }
//                     }
//                     Err(e) =>{}
//                 }
//             }
//         }

//         // println!("success: {}", s_count);
//         // println!("failure: {}", f_count);

//         Ok(())
//     }
// }

//         let dummy_tx: Transaction = Transaction {
//     version: 2,
//     locktime: 538770804,
//     vin: vec![
//         Input {
//             txid: "b7e74d40d17b1a3372f18b1f9738e4c2c8a0118f90de248b669eea2c13a350a5".to_string(),
//             vout: 0,
//             prevout: Prevout {
//                 scriptpubkey: "00209adf8dd8a29f549657d2bf31dcb3dfefc50a4005dc49d636ce29e6198d6603a1".to_string(),
//                 scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 9adf8dd8a29f549657d2bf31dcb3dfefc50a4005dc49d636ce29e6198d6603a1".to_string(),
//                 scriptpubkey_type: "v0_p2wsh".to_string(),
//                 scriptpubkey_address: "bc1qnt0cmk9zna2fv47jhucaev7lalzs5sq9m3yavdkw98npnrtxqwss9d24pw".to_string(),
//                 value: 30000,
//             },
//             scriptsig: Some("".to_string()),
//             scriptsig_asm: Some("".to_string()),
//             witness: Some(vec![
//                 "".to_string(),
//                 "304402204f0ea1a9dc61dccd8874bd420060929cc21dd0b6ea2ddcd1fb8dabcc2ff532ca0220546baccc94c63cf8ad913763ec0dd7602837f71f4271087ebc3884e400b3ff7e01".to_string(),
//                 "30440220039d97d571c96440de1a49a1f05cca88b5ad53271af9d5a77e93f2b548185851022053afd5412cf025868e313281ebc74348766e9edeb594a7bfb5eb745f4d73a4b201".to_string(),
//                 "52210241138f9570c0cf7a91ed8f60b28ada6c77e6203339f0d13ae41fc431e25763492102944259faa6a3bc5c4403b55c8675e063ec00665e37c050808a18645010ec39f952ae".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 2162938768,
//             inner_redeemscript_asm: None,
//         },
//         // Add second input here
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "0020b641fec4ab9990c569429ac4e4194530513a088742d9cefb60aa5437a72f38e7".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 b641fec4ab9990c569429ac4e4194530513a088742d9cefb60aa5437a72f38e7".to_string(),
//             scriptpubkey_type: "v0_p2wsh".to_string(),
//             scriptpubkey_address: Some("bc1qkeqla39tnxgv262zntzwgx29xpgn5zy8gtvua7mq4f2r0fe08rnsrxh0zl".to_string()),
//             value: 330,
//         },
//         Output {
//             scriptpubkey: "0020fa0344234fbe1131f5d2570b5a4c0a3a11fcf0220c13585ca569e8551c1bc6aa".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 fa0344234fbe1131f5d2570b5a4c0a3a11fcf0220c13585ca569e8551c1bc6aa".to_string(),
//             scriptpubkey_type: "v0_p2wsh".to_string(),
//             scriptpubkey_address: Some("bc1qlgp5gg60hcgnrawj2u945nq28ggleupzpsf4sh99d85928qmc64q0y87ku".to_string()),
//             value: 330,
//         },
//         Output {
//             scriptpubkey: "0020f2d8d646a643eda05a075c42cab2ba8a19b865032ee7fb1350f2effa6b88aa13".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 f2d8d646a643eda05a075c42cab2ba8a19b865032ee7fb1350f2effa6b88aa13".to_string(),
//             scriptpubkey_type: "v0_p2wsh".to_string(),
//             scriptpubkey_address: Some("bc1q7tvdv34xg0k6qks8t3pv4v463gvmsegr9mnlky6s7thl56ug4gfsmyeqg3".to_string()),
//             value: 600,
//         },
//         Output {
//             scriptpubkey: "00201b1c47adaacd9027e6364be10fd43f1bb412485a0f37e0467ab4e22f5177225b".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 1b1c47adaacd9027e6364be10fd43f1bb412485a0f37e0467ab4e22f5177225b".to_string(),
//             scriptpubkey_type: "v0_p2wsh".to_string(),
//             scriptpubkey_address: Some("bc1qrvwy0td2ekgz0e3kf0ssl4plrw6pyjz6pum7q3n6kn3z75thyfds0mvrfe".to_string()),
//             value: 6400,
//         },
//         Output {
//             scriptpubkey: "00209c54e1227261a605645b8dd297581a03dbcaa79b84298ff10baca8889959ba1a".to_string(),
//             scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 9c54e1227261a605645b8dd297581a03dbcaa79b84298ff10baca8889959ba1a".to_string(),
//             scriptpubkey_type: "v0_p2wsh".to_string(),
//             scriptpubkey_address: Some("bc1qn32wzgnjvxnq2ezm3hffwkq6q0du4fumss5clugt4j5g3x2ehgdqjeq2pq".to_string()),
//             value: 19100,
//         },
//     ]
// };

//         let dummy_tx: Transaction = Transaction {
//     version: 1,
//     locktime: 0,
//     vin: vec![
//         Input {
//             txid: "8502bc65a8e9b11996a912da4eb42378c57b6a89a0c940422a9e61e62e5932e1".to_string(),
//             vout: 0,
//             prevout: Prevout {
//                 scriptpubkey: "002032cf73321cba9ba880807cd10cc9d58d73b25a8b1e9910662ece538e6ed6860f".to_string(),
//                 scriptpubkey_asm: "OP_0 OP_PUSHBYTES_32 32cf73321cba9ba880807cd10cc9d58d73b25a8b1e9910662ece538e6ed6860f".to_string(),
//                 scriptpubkey_type: "v0_p2wsh".to_string(),
//                 scriptpubkey_address: "bc1qxt8hxvsuh2d63qyq0ngsejw434emyk5tr6v3qe3weefcumkksc8s40skt0".to_string(),
//                 value: 7320,
//             },
//             scriptsig: Some("".to_string()),
//             scriptsig_asm: Some("".to_string()),
//             witness: Some(vec![
//                 "9ace113fc000919095b4fedd321e560cd14652ce208ed5bfdf43c4c6015211ad".to_string(),
//                 "3045022100aaa95ed8cf4d2e2a5c7d1d38fa18b12a0af4a3a699cd28e6d8081dd1984a625402202e8978041cb6005a43274bf96322f2add910643bcc9b8862be25dee1eedf20d301".to_string(),
//                 "3045022100ecd9f8e3fcb94bbefa00ba8833ad3bf04e8e156cbb7649c50b17e983e70782c602204c412b7b69650d7fda78666994b0856a72eeafccfd288a71b79d63fd28c77e1301".to_string(),
//                 "2103c9cdeed621eeb531138e1910c7a318f4a0f9fa2d24c5094b5f973cbe743f901cac6476a914bc931f3a7bcf1dd3ec0372cad56d7f3d8382a76788ad03dcbb0cb16721028e08c22a13a1ec0eec797ff0bffb334f930e2b92ed929814d14458e501bd20cbad82012088a91415d6bdfc2cd8d245ac6afe8c24385bd4155b2f778768".to_string(),
//             ]),
//             is_coinbase: false,
//             sequence: 4294967295,
//             inner_redeemscript_asm: None,
//         },
//         // Second input (no second input provided in the new transaction)
//     ],
//     vout: vec![
//         Output {
//             scriptpubkey: "51208ba512ebc3df0512af9048f74c20694a4aae4b8d7e2d55a906d54ffac6348c30".to_string(),
//             scriptpubkey_asm: "OP_PUSHNUM_1 OP_PUSHBYTES_32 8ba512ebc3df0512af9048f74c20694a4aae4b8d7e2d55a906d54ffac6348c30".to_string(),
//             scriptpubkey_type: "v1_p2tr".to_string(),
//             scriptpubkey_address: Some("bc1p3wj3967rmuz39tusfrm5cgrfff92ujud0ck4t2gx648l43353scq2m6emr".to_string()),
//             value: 5000,
//         },
//         // Second output (no second output provided in the new transaction)
//     ]
// };
