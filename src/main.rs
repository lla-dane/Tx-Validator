mod block_mine;
mod error;
mod transaction;
mod validation_checks;

use crate::error::Result;


use crate::validation_checks::all_transaction_verification;
use crate::block_mine::block::valid_block_header;

fn main() -> Result<()> {
    
    all_transaction_verification()?;


    valid_block_header()?;

    Ok(())
}
