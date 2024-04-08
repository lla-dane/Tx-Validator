use crate::{error::Result, tx};
use std::{collections::HashMap, fmt::format, fs::File, io::Write, slice::Windows};

use crate::transaction::Transaction;

use super::serialise_tx::{create_txid_tx_map, double_sha256};

pub fn generate_roots(
    map: Vec<(String, Transaction, String, usize, u64)>,
) -> Result<(String, String, String)> {
    let tx_weight_limit = 3000000;
    let mut current_tx_weight = 0;
    let mut txid_vec: Vec<String> = Vec::new();
    let mut txid_le_vec: Vec<String> = Vec::new();
    let mut wtxid_vec: Vec<String> = Vec::new();
    let mut block_subsidy = 0;

    wtxid_vec.push("0000000000000000000000000000000000000000000000000000000000000000".to_string());

    for (txid, _, wtxid, weight, fees) in map {
        if current_tx_weight >= tx_weight_limit {
            break;
        }
        current_tx_weight += weight;
        block_subsidy += fees;

        txid_le_vec.push(txid.clone());

        let mut txid_reversed_bytes = hex::decode(txid)?;
        txid_reversed_bytes.reverse();
        let natural_txid = hex::encode(txid_reversed_bytes);

        let mut wtxid_reversed_bytes = hex::decode(wtxid)?;
        wtxid_reversed_bytes.reverse();
        let natural_wtxid = hex::encode(wtxid_reversed_bytes);

        txid_vec.push(natural_txid);
        wtxid_vec.push(natural_wtxid);
    }

    let witness_root_hash = merkel_root(wtxid_vec)?;

    let (coinbase_tx, txid_coinbase_tx) = create_coinbase(witness_root_hash, block_subsidy)?;

    let coinbase_txid = hex::encode(double_sha256(&hex::decode(&txid_coinbase_tx)?));

    txid_vec.insert(0, coinbase_txid.clone());

    let merkel_root = merkel_root(txid_vec)?;

    Ok((merkel_root, coinbase_tx, coinbase_txid))
}

fn merkel_root(txids: Vec<String>) -> Result<String> {
    if txids.len() == 1 {
        return Ok(txids[0].clone());
    }

    let mut result = Vec::new();

    // ITERATE OVER TXIDS IN PAIRS
    for chunk in txids.chunks(2) {
        let concat = if chunk.len() == 2 {
            // CONCATENATE EACH PAIR
            format!("{}{}", chunk[0], chunk[1])
        } else {
            // DUPLICATE OF ITS ALONE
            format!("{}{}", chunk[0], chunk[0])
        };

        let parent_hex = double_sha256(&hex::decode(concat)?);
        result.push(hex::encode(parent_hex));
    }

    // RECURSIVELY PROCESS THE NEXT LEVEL
    merkel_root(result)
}

pub fn create_coinbase(witness_root_hash: String, block_subsidy: u64) -> Result<(String, String)> {
    /*
    VERSION
    INPUT COUNT:
    INPUTS [
        {
            TXID:
            VOUT
            SCRIPT SIG SIZE
            SCRIPT SIG
            SEQUENCE
        }
    ]
    OUTPUT COUNT:
    OUTPUT [
    1:    {
            AMOUNT:
            SCRIPT PUB KEY SIZE
            SCRIPT PUB KEY
        }
    2:  {
            AMOUNT:
            SCRIPT PUB KEY SIZE
            SCRIPT PUB KEY
        }
    ]
    WITNESS [\
        {
            STACK ELEMENTS
            {
                SIZE
                ITEM
            }
        }
    ]
    LOCKTIME
     */

    let mut coinbase_tx = String::new();
    let mut txid_coinbase_tx = String::new();

    let block_amount = 650082296 + block_subsidy;

    let witness_reserved_value =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let witness_commit = format!("{}{}", witness_root_hash, witness_reserved_value);

    let wtxid_commit = hex::encode(double_sha256(&hex::decode(&witness_commit)?));

    let wtxid_commitment = format!("{}{}", "6a24aa21a9ed", wtxid_commit);

    // VERSION MARKER FLAG
    coinbase_tx.push_str("01000000");
    txid_coinbase_tx.push_str("01000000");

    coinbase_tx.push_str("0001");

    // INPUT COUNT
    coinbase_tx.push_str("01");
    txid_coinbase_tx.push_str("01");

    // INPUT
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");
    coinbase_tx.push_str("ffffffff");
    coinbase_tx.push_str("25");
    coinbase_tx
        .push_str("03a0bb0d184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100");
    coinbase_tx.push_str("ffffffff");

    // OUTPUT COUNT
    coinbase_tx.push_str("02");

    // OUTPUT
    coinbase_tx.push_str(&hex::encode(block_amount.to_le_bytes()));
    coinbase_tx.push_str("19");
    coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac");

    coinbase_tx.push_str("0000000000000000");
    coinbase_tx.push_str("26");
    coinbase_tx.push_str(&wtxid_commitment);

    // ------------------TXID--------------------------

    // INPUT
    txid_coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");
    txid_coinbase_tx.push_str("ffffffff");
    txid_coinbase_tx.push_str("25");
    txid_coinbase_tx
        .push_str("03a0bb0d184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100");
    txid_coinbase_tx.push_str("ffffffff");

    // OUTPUT COUNT
    txid_coinbase_tx.push_str("02");

    // OUTPUT
    txid_coinbase_tx.push_str(&hex::encode(block_amount.to_le_bytes()));
    txid_coinbase_tx.push_str("19");
    txid_coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac");

    txid_coinbase_tx.push_str("0000000000000000");
    txid_coinbase_tx.push_str("26");
    txid_coinbase_tx.push_str(&wtxid_commitment);

    // -----------------TXID----------------------------

    // WITNESS
    coinbase_tx.push_str("01");
    coinbase_tx.push_str("20");
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");

    coinbase_tx.push_str("00000000");
    txid_coinbase_tx.push_str("00000000");

    Ok((coinbase_tx, txid_coinbase_tx))
}

#[cfg(test)]

mod test {
    use crate::validation_checks::double_sha256;

    use super::*;

    #[test]
    fn merkel_test() -> Result<()> {
        let tx = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9ed52484daa9558fd003c94c61c410ff8eddf264f896a0f46c3b661ff2b30cfbd9c0120000000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        let txid = hex::encode(double_sha256(&hex::decode(&tx)?));

        println!("{}", txid);

        Ok(())
    }
}
