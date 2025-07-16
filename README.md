# AnchorWatch Sovereign Recovery Tool

This is an AnchorWatch product for sovereign recovery path, allowing you to recover funds without using any AnchorWatch software.

The python script `recover.py` will allow you to spend your Trident Vault bitcoin without using any AnchorWatch software once your timelocks expire by doing the following steps:

1. Connect to your own bitcoin node to create an unsigned PSBT (Partially Signed Bitcoin Transaction) using the correct block height of your vault (by setting the correct nLockTime). This will create a send all transaction to an address of your chosing, with the fee rate of your chosing.
2. Connect with your Ledgers to sign the spend all transaction (2 of your 3 ledgers are required.)
3. Use your node to combine the partially signed transactions from each ledger, combine the signatures, and finalize it into a valid bitcoin transaction.
4. Attempt to broadcast the transaction, if the timelock has not been satisifed yet, it will be written to `final_tx.txt` in this directory.

**Important:** Assumes Bitcoin node (e.g., Bitcoin Core) and two of your Three Ledger wallets used in your Trident Vault, and information from your soverign recovery kit.

## Prerequisites

1. **Set up a Bitcoin Node**
   - Have a fully synced bitcoin node. For best performance, use a full node, a pruned node will work, but will require you reindex the block chain to be able to process all of your UTXOs.
2. **Configure Bitcoin Core:**
   - Update bitcoin.conf (Preferences > Open Configuration File in Bitcoin Core):
     ```
     server=1
     rpcuser=your_username
     rpcpassword=your_password
     rpcallowip=127.0.0.1
     ```
   - Restart Bitcoin Core.

3. **Load Output Descriptor:** Use `importdescriptors` command from your AnchorWatch recovery kit to load the wallet descriptor into Bitcoin Core.


## Setup on Clean Computer

1. **Clone Repository:**
   ```
   git clone https://github.com/AnchorWatch/soverign_recovery.git
   cd soverign_recovery
   ```

2. **Run Installation Script:**
   ```
   ./install.sh
   ```
   (On Linux: This may require sudo for installing system dependencies like libusb-1.0-0-dev and libudev-dev. On macOS, no additional dependencies are needed.)

3. **Update Config Files:**
   - Take the file on the recovery page labeled "Signing Information" and replace the contents of `config.json` with the signing data.
   - Update the contents of `node_config.json` so it matches your rpcuser, rpcpassword, and wallet name as set up in Bitcoin Core.

3. **Run the Script:**
   ```
   source .venv/bin/activate
   python recover.py
   ```

If the recovery script is run prior to the timelock expiring, the Bitcoin network will not accept the transaction. The script will place a copy of the final signed bitcoin transaction in the file `final_tx.txt`. This can be broadcasted with your local node using `sendrawtransaction`, software like Sparrow Wallet (File -> Open Transaction -> From Text), or mempool.space's broadcast service at: https://mempool.space/tx/push.

If a current or former AnchorWatch customer has any questions, please reach out to rob (at) anchorwatch (dot) com for support!


## License

This software is released under the MIT License. See the [LICENSE](LICENSE) file for details.

