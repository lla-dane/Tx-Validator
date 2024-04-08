mod error;
mod tx;
mod transaction;
mod validation_checks;
mod block_mine;

use serde_json::to_string_pretty;
use transaction::load_mempool_transactions;
use tx::load_transactions;
use crate::error::Result;

fn main() -> Result<()>{

    load_transactions();
    Ok(())
}
