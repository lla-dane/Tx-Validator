use crate::error::Result;

use crate::transaction::Transaction;

use super::serialise_tx::double_sha256;

// RETURNS THE MERKEL ROOT, COINBASE TX, COINBASE TXID AND TXIDS TO BE INCLUDED IN THE BLOCK
pub fn generate_roots(
    map: Vec<(String, Transaction, String, usize, u64)>,
) -> Result<(String, String, String, Vec<String>)> {
    let tx_weight_limit = 3993000;
    let mut current_tx_weight = 0;
    let mut txids: Vec<String> = Vec::new();
    let mut wtxids: Vec<String> = Vec::new();
    let mut block_subsidy = 0;

    wtxids.push("0000000000000000000000000000000000000000000000000000000000000000".to_string());

    for (txid, _, wtxid, weight, fees) in map {
        if current_tx_weight >= tx_weight_limit {
            break;
        }
        current_tx_weight += weight;
        block_subsidy += fees;

        txids.push(txid);
        wtxids.push(wtxid);
    }

    let witness_root_hash = merkel_root(wtxids)?;

    let (coinbase_tx, txid_coinbase_tx) = create_coinbase(witness_root_hash, block_subsidy)?;

    let mut coinbase_txid_bytes = double_sha256(&hex::decode(&txid_coinbase_tx)?);
    coinbase_txid_bytes.reverse();

    let coinbase_txid = hex::encode(coinbase_txid_bytes);

    txids.insert(0, coinbase_txid.clone());

    let merkel_root = merkel_root(txids.clone())?;

    Ok((merkel_root, coinbase_tx, coinbase_txid, txids))
}

// FUNCTION TO CREATE THE MERKEL ROOT FOR A VECTOR OF TXIDS
fn merkel_root(txids: Vec<String>) -> Result<String> {
    let mut txids_natural: Vec<String> = Vec::new();

    for txid in txids.iter() {
        let mut txid_bytes = hex::decode(txid)?;
        txid_bytes.reverse();

        txids_natural.push(hex::encode(txid_bytes));
    }

    while txids_natural.len() > 1 {
        let mut next_level = Vec::new();

        // IF ODD NUMBER OF TXID, DUPLICATE THE LAST ONE 
        if txids_natural.len() % 2 != 0 {
            txids_natural.push(txids_natural.last().unwrap().clone());
        }

        for chunk in txids_natural.chunks(2) {
            match chunk {
                [one, two] => {
                    let concat = one.to_owned() + two;
                    next_level.push(hex::encode(double_sha256(&hex::decode(&concat)?)));
                }
                _ => unreachable!(), // This case should never happen due to the duplication logic above
            }
        }

        txids_natural = next_level;
    }

    Ok(txids_natural[0].clone())
}

// CREATE THE COINBASE TX AND COINBASE TXID
pub fn create_coinbase(witness_root_hash: String, block_subsidy: u64) -> Result<(String, String)> {
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

    // println!("{}", wtxid_commitment);

    Ok((coinbase_tx, txid_coinbase_tx))
}

// TO TEST MY CODE DURING DEVELOPMENT
#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn merkel_test() -> Result<()> {
        let txids = vec![
            "2ec4532bbb79b5875f3e86cf11f3f1e42b74717c573368a92558cff7b1033365".to_string(),
            "958ffdb52a9148d3a6fca79d21d6b17e146c94909f6e63dd7723e409b10a1cd2".to_string(),
            "dbba5fdfee9cb36e4f80db9ed7daebaa1460f9836bb0328db2f9f2dc4cd02d14".to_string(),
        ];

        let merkel_root = merkel_root(txids)?;

        println!("{}", merkel_root);

        Ok(())
    }
}
