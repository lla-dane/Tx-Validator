## ASSIGNMENT REPORT

The aim of the assignment was to mine a set of transactions in the mempool into a block, while correctly validating them as per the concensus rules.


### DESIGN APPROACH: 
1. At first I iterated through the mempool and verified transaction on the basis of their script types (`p2tr` transactions are added in block with only basic checks like sufficient gas-fees)
   and inserted in the valid-mempool.
2. Transactions with gas fees less than 1500 sats are rejected.
3. Then a map of all valid-transaction which includes `txid`, `transaction`, `wtxid`, `tx_weight` and `fees` is created for each of them.
4. Then the wtxid commintment is created from all the wtxids of the valid transactions as mentioned in learn me a bitcoin.
5. Then the coinbase transaction is hard-coded.
6. Then the merkel root is created using the txids of all valid transactions withtthe txid if coinbase at the top.
7. Then a valid-block-header is created by implementing the POW algorithm by continuously increasing the nonce once on each failure.
8. Finally the valid-block header is created and, coinbase tx and all txids are inserted in the output.txt. 

### IMPLEMENTATION DETAILS:

#### CODEBASE ARCHITECTURE
The code is divided into two main parts ``block_mine`` and `validation_checks`.

#### VALIDATION_CHECKS
The core verification logic of `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh` transactions are implemented here.

##### P2PKH VERIFICATION: 
1) In `input_verification_p2pkh`, the script_sig_asm and script_pubkey_asm are extracted from the input of the transaction being verified  and then
   passed `script_execution`
2) `HASH160` of `Public key` in `script_sig_asm` is verified with `pubkeyhash` in the script_pub_key
3) Now the `signature` and `public_key` are pushed in the stack and the opcodes in the script_sig_asm are executed in sequence.
4) The `verify_ecdsa` function is then used to verify the signature against the pubic key and the message created from the transaction as per the consensus rules.
5) I refered to [this](https://github.com/LivioZ/P2PKH-Bitcoin-tx-verifier?tab=readme-ov-file) repository for `trimmed_tx` creation for signature verification.

##### P2SH VERIFICATION: 
There are 3 types of p2sh transactions: `native p2sh`, `p2sh-p2wpkh`, `p2sh-p2wsh` 

###### LEGACY P2SH: 
1. The scripts are executed in a stack.
2. Sequence of script execution: `script_sig`, `script_pub_key`,  `inner_redeem_script`.
3. The logic for all opcodes present in scripts are implemented in `p2sh.rs`
4. The `trimmed_tx` creation is same as the `p2pkh` just instead of `script_sig_asm`, `inner_redeem_script` is used.

###### P2SH-P2WPKH: 
1. Scripts are executed in the stack.
2. All relevant `opcodes` logic implementation are in `p2sh.rs`. 
3. `script_sig` and `script_pub_key` are executed in the same way.
4. Here instead of `inner_redeem_script`, witness is executed.
5. `signature` and `public key` are pushed in the stack.
6. Now `OP_DUP`, `OP_HASH160` are executed implicitely.All relevant `opcodes` logic implementation are in `p2sh.rs`. 
7. Now `inner_redeem_script` opcodes are executed.
8. Again `OP_EQUALVERIFY` and `OP_CHECKSIG` are excuted implicitely.

###### P2SH-P2WSH: 
1. Scripts are executed in the stack.
2. All relevant `opcodes` logic implementation are in `p2sh.rs`. 
3. `script_sig` and `script_pub_key` are executed in the same way.
4. Here also instead of `inner_redeem_script`, witness is executed.
5. All the elements except the last element in the `witness` are pushed in the stack.
6. Now the `witness-script` is executed which is the last element in the witness.
7. Each opcode is iterated and executed, the final result is procured.

`SIGNATURE` verification for segwit `p2sh` transactions are refrenced from [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).

##### P2WPKH:
1. This verification is not implemented using stack.
2. The `signature` and `public key` are extracted from the witness as there are only two elements in all `p2wpkh` transactions.
3. `HASH160` of `public key` is verified against the `pubkeyhash` in `script_pub_key`.
4. Now the `signature` is verified against the `message` and `public key` using `verify_ecdsa` function.

##### P2WSH: 
1. Scripts are executed in the stack.
2. All relevant `opcodes` logic implementation are in `p2wsh.rs`.
3. All elements in the `witness` except the last element which is the `witness script` are pushed in the stack.
4. Now the `witness-program` which is the last element is the `script_pub_key` is cross-verified with the `SHA256` of `witness-script`.
5. Now after this verfication all the opcodes in the `witness-script` is executed in the sequence and the final result is procured.

#### `mod.rs` in `validation_checks` contains: 
1. Logic of `OP_CHECKSIG` and `OP_MULTICHECKSIG`.
2. `verify_tx` method which redirects transctions on the basis of their types.
3. `all_transaction_verification` iterates through the mempool and executes `verify_tx` for each transaction while also checking for double spends.


#### BLOCK MINE
The core logic of block mining is implemented here.

##### `serialise_tx.rs`
1. The transactions which are valid under the consensus rules are put in the valid-mempool directory.
2. Now in `create_txid_tx_map` the `valid-mempool` directory is iterated and each valid transaction is seriliased into raw transactions.
3. Now as the transactions are iterated in the valid-mempool, their `txid`, `transaction`, `wtxid`, `tx_weight` and `fees`is insert in a vector in the descending order of their
   `gas-fees`/`tx-weight`.
4. Method to serialise a transaction into its raw transaction format is referenced from [learnmeabitcoin](https://learnmeabitcoin.com/).

##### `merkle_root.rs`
1. The `merkel_root` and `coinbase_transaction` logic is implemented here.

##### `block.rs`
1. Here a `valid_block_header` is created using POW against the block_header_hash and the target bits.

At the end the `valid_block_header`, `raw coinbase_tx` , `txids` are inserted in the output.txt.

### RESULTS AND PERFORMANCE: 
A valid block is created with: 
1. BLOCK WEIGHT := 3994072
2. FEE := 21619204
3. SCORE: 101
4. NUMBER OF TRANSACTIONS: 4453

Effieciency of my solution could have been improved from the following changes: 
1. Making a single `opcode` registry for all transaction types and not implementing the `opcode` logic in each tx verification file.
2. Could not include `p2sh` transactions in `output.txt` because of some bugs at the last moment.

### CONCLUSION: 

##### REFRENCES: 
1) Github repo - [p2pkh verification](https://github.com/LivioZ/P2PKH-Bitcoin-tx-verifier?tab=readme-ov-file)
2) [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) - for signature verification of segwit transactions.
3) [Learn me a bitcoin](https://learnmeabitcoin.com/) - for block-header and coinbase transaction composition 

 
