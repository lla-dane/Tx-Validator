use crate::{error::Result, tx};
use std::{collections::HashMap, fmt::format, slice::Windows};

use crate::transaction::Transaction;

use super::serialise_tx::{create_txid_tx_map, double_sha256};

pub fn generate_rootss(map: Vec<(String, Transaction, String, usize, u64)>) -> Result<()> {
    let tx_weight_limit = 3000000;
    let mut current_tx_weight = 0;
    let mut txid_vec: Vec<String> = Vec::new();
    let mut wtxid_vec: Vec<String> = Vec::new();

    wtxid_vec.push("0000000000000000000000000000000000000000000000000000000000000000".to_string());

    for (txid, _, wtxid, weight, fees) in map {
        if current_tx_weight >= tx_weight_limit {
            break;
        }
        current_tx_weight += weight;

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

    let coinbase_tx = create_coinbase(witness_root_hash)?;
    let coinbase_txid = hex::encode(double_sha256(&hex::decode(&coinbase_tx)?));

    txid_vec.insert(0, coinbase_txid);

    let merkel_root = merkel_root(txid_vec)?;

    Ok(())
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

pub fn create_coinbase(witness_root_hash: String) -> Result<String> {
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

    let witness_reserved_value =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let witness_commit = format!("{}{}", witness_root_hash, witness_reserved_value);

    let wtxid_commit = hex::encode(double_sha256(&hex::decode(&witness_commit)?));

    let wtxid_commitment = format!("{}{}", "6a24aa21a9ed", wtxid_commit);

    // VERSION MARKER FLAG
    coinbase_tx.push_str("01000000");
    coinbase_tx.push_str("0001");

    // INPUT COUNT
    coinbase_tx.push_str("01");

    // INPUT
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");
    coinbase_tx.push_str("ffffffff");
    coinbase_tx.push_str("25");
    coinbase_tx
        .push_str("03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100");
    coinbase_tx.push_str("ffffffff");

    // OUTPUT COUNT
    coinbase_tx.push_str("02");

    // OUTPUT
    coinbase_tx.push_str("f595814a00000000");
    coinbase_tx.push_str("19");
    coinbase_tx.push_str("76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac");

    coinbase_tx.push_str("0000000000000000");
    coinbase_tx.push_str("26");
    coinbase_tx.push_str(&wtxid_commitment);

    // WITNESS
    coinbase_tx.push_str("01");
    coinbase_tx.push_str("20");
    coinbase_tx.push_str("0000000000000000000000000000000000000000000000000000000000000000");

    coinbase_tx.push_str("00000000");

    Ok(coinbase_tx)
}

#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn coinbae_test() -> Result<()> {
        let result = create_coinbase(
            "f12d56f2234e809129dbf59392961bbe7a89b6250651f6aea7852cc00ced63ff".to_string(),
        )?;

        println!("{}", result);

        Ok(())
    }

    #[test]
    fn merkel_test() -> Result<()> {
        let txids = vec![
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87".to_string(),
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4".to_string(),
            "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4".to_string(),
            "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d".to_string(),
        ];

        let mut txids_natural = Vec::new();

        for txid in txids {
            let mut txid_natural_bytes = hex::decode(txid)?;
            txid_natural_bytes.reverse();

            let txid_natural_hex = hex::encode(txid_natural_bytes);

            txids_natural.push(txid_natural_hex);
        }

        let result = merkel_root(txids_natural)?;

        println!("{}", result);

        Ok(())
    }
}
