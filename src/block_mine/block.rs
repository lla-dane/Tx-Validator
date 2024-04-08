use std::{fs::File, io::Write};

use num_bigint::BigUint;
use num_traits::Num;

use crate::{block_mine::serialise_tx::double_sha256, error::Result};

use super::{merkle_root::generate_roots, serialise_tx::create_txid_tx_map};

fn target_to_compact(target_hex: &str) -> u32 {
    let target_bytes = hex::decode(target_hex).expect("Decoding failed");
    let non_zero_pos = target_bytes
        .iter()
        .position(|&x| x != 0)
        .unwrap_or(target_bytes.len());
    let size = target_bytes.len() - non_zero_pos;

    // Get the first three significant bytes as mantissa
    let mut mantissa: [u8; 3] = [0; 3];
    for (i, &byte) in target_bytes.iter().skip(non_zero_pos).take(3).enumerate() {
        mantissa[i] = byte;
    }

    // Calculate compact representation
    let compact = ((size as u32) << 24)
        + ((mantissa[0] as u32) << 16)
        + ((mantissa[1] as u32) << 8)
        + mantissa[2] as u32;

    compact
}

pub fn valid_block_header() -> Result<()> {
    let version_int: u32 = 4;
    let version = hex::encode(version_int.to_le_bytes());

    let prev_block_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let map = create_txid_tx_map()?;
    let (merkel_root, coinbase_tx, coinbase_txid) = generate_roots(map.clone())?;

    let time_stamp_int: u32 = 1712571823;
    let time_stamp = hex::encode(time_stamp_int.to_le_bytes());

    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target_int = BigUint::from_str_radix(target, 16).expect("Invalid hex in block hash");
    let bits = target_to_compact(target);
    let bits_hex = format!("{:08x}", bits);

    let mut nonce: u32 = 0;

    // let nonce_max: u32 = 4294967295;

    let valid_block_header: String;

    loop {
        let nonce_hex = hex::encode(nonce.to_le_bytes());

        let mut block_header: String = String::new();

        block_header.push_str(&version);
        block_header.push_str(&prev_block_hash);
        block_header.push_str(&merkel_root);
        block_header.push_str(&time_stamp);
        block_header.push_str(&bits_hex);
        block_header.push_str(&nonce_hex);

        let block_hash = hex::encode(double_sha256(&hex::decode(&block_header)?));

        let block_hash_int =
            BigUint::from_str_radix(&block_hash, 16).expect("Invalid hex in block hash");

        if block_hash_int <= target_int {
            // println!("Valid nonce found: {}", nonce);
            // println!("Block header: {}", block_header);
            // println!("Hash: {}", block_hash);

            valid_block_header = block_header;
            break;
        }

        nonce += 1;
    }

    // BLOCK HEADER
    // COINBASE TX
    // COINBASE TXID
    // REGULAR TXID

    let mut coinbase_txid_le = hex::decode(&coinbase_txid)?;
    coinbase_txid_le.reverse();

    let coinbase_txid_le_hex = hex::encode(coinbase_txid_le);

    let mut block_file = File::create("./output.txt")?;

    writeln!(block_file, "{}", valid_block_header)?;
    writeln!(block_file, "{}", coinbase_tx)?;
    writeln!(block_file, "{}", coinbase_txid_le_hex)?;

    for (txid, _, _, _, _) in map {
        writeln!(block_file, "{}", txid)?;
    }

    Ok(())
}

#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn block_test() -> Result<()> {
        // valid_block_header();

        Ok(())
    }
}
