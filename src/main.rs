mod block_mine;
mod error;
mod transaction;
mod validation_checks;

use crate::error::Result;


use crate::validation_checks::all_transaction_verification;
use crate::block_mine::block::valid_block_header;

fn main() -> Result<()> {
    
    // TRANSACTION VERIFICATION FUNCTION
    all_transaction_verification()?;

    println!("TRANSACTION VERIFICATION: COMPLETED");

    // BLOCK MINING
    valid_block_header()?;

    Ok(())
}
