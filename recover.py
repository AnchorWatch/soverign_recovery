import json
import os
import re
import datetime
import decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from ledger_bitcoin import createClient, Chain, WalletPolicy
from ledger_bitcoin.psbt import PSBT

with open('node_config.json', 'r') as f:
    node_config = json.load(f)
RPC_USER = node_config['rpc_user']
RPC_PASS = node_config['rpc_pass']
RPC_HOST = node_config['rpc_host']
RPC_PORT = node_config['rpc_port']
WALLET_NAME = node_config['wallet_name']

def validate_node_config():
    try:
        with open('node_config.json', 'r') as f:
            data = json.load(f)
        required = ['rpc_user', 'rpc_pass', 'rpc_host', 'rpc_port', 'wallet_name']
        missing = [k for k in required if k not in data]
        if missing:
            print(f"Missing keys in node_config.json: {', '.join(missing)}")
            return False
        return True
    except Exception as e:
        print(f"Error loading node_config.json: {e}")
        return False

def validate_config():
    try:
        with open('config.json', 'r') as f:
            data = json.load(f)
        required = ['ledgerID', 'walletName', 'descriptorTemplate', 'signingKeys']
        missing = [k for k in required if k not in data]
        if missing:
            print(f"Missing keys in config.json: {', '.join(missing)}")
            print("Did you update the config.json file with the contents of your recovery kit in the Signing Information section?")
            return False
        if not isinstance(data['signingKeys'], list):
            print("signingKeys must be a list")
            print("Did you update the config.json file with the contents of your recovery kit in the Signing Information section?")
            return False
        for key in data['signingKeys']:
            key_required = ['hmac_buffer', 'formatted_key', 'description_template_position']
            key_missing = [k for k in key_required if k not in key]
            if key_missing:
                print(f"Missing keys in signingKeys entry: {', '.join(key_missing)}")
                print("Did you update the config.json file with the contents of your recovery kit in the Signing Information section?")
                return False
        return True
    except Exception as e:
        print(f"Error loading config.json: {e}")
        print("Did you update the config.json file with the contents of your recovery kit in the Signing Information section?")
        return False

def connect_rpc():
    return AuthServiceProxy(f"http://{RPC_USER}:{RPC_PASS}@{RPC_HOST}:{RPC_PORT}/wallet/{WALLET_NAME}")

def create_psbt(rpc, output_address, fee_rate):
    with open('config.json', 'r') as f:
        config = json.load(f)
    descriptor = config['descriptorTemplate']
    after_values = [int(m.group(1)) for m in re.finditer(r'after\((\d+)\)', descriptor)]
    if not after_values:
        raise ValueError('No valid after() values found in descriptor')
    nlocktime = max(after_values)
    human_time = datetime.datetime.fromtimestamp(nlocktime).strftime('%Y-%m-%d %H:%M:%S')
    print(f'Using nlocktime: {nlocktime} ({human_time})')

    utxos = rpc.listunspent(1, 9999999)
    if not utxos:
        print("No UTXOs found.")
        return None

    inputs = [{"txid": u['txid'], "vout": u['vout']} for u in utxos]
    amount_sats = sum(int(u['amount'] * 100000000) for u in utxos)
    outputs = [{output_address: amount_sats / 100000000.0}]
    options = {
        "subtractFeeFromOutputs": [0],
        "fee_rate": fee_rate,
        "locktime": nlocktime
    }
    result = rpc.walletcreatefundedpsbt(inputs, outputs, nlocktime, options, True)
    return result['psbt']

def sign_with_ledger():
    with open('config.json', 'r') as f:
        config = json.load(f)

    with createClient(chain=Chain.MAIN) as client:
        fpr = client.get_master_fingerprint().hex()
        print(f"Master key fingerprint: {fpr}")

        device_xpub = client.get_extended_pubkey("m/48'/0'/0'/2'")

        policy_name = config['walletName']
        expected_policy_id = config['ledgerID']
        descriptor_template = config['descriptorTemplate']
        keys_info = [key['formatted_key'] for key in config['signingKeys']]

        policy = WalletPolicy(
            name=policy_name,
            descriptor_template=descriptor_template,
            keys_info=keys_info
        )

        matching_key = None
        for key in config['signingKeys']:
            if ']' in key['formatted_key']:
                formatted_xpub = key['formatted_key'].split(']', 1)[1]
                if formatted_xpub == device_xpub:
                    matching_key = key
                    break

        if not matching_key:
            print(f"No matching key found for device_xpub: {device_xpub}")
            return None

        if matching_key['hmac_buffer'] is not None:
            policy_hmac = bytes.fromhex(matching_key['hmac_buffer'])
        else:
            print("No HMAC found. Registering...")
            policy_id_bytes, new_hmac = client.register_wallet(policy)
            policy_id = policy_id_bytes.hex()
            if policy_id != expected_policy_id:
                print(f"Policy ID mismatch! Got: {policy_id}, Expected: {expected_policy_id}")
                return None
            matching_key['hmac_buffer'] = new_hmac.hex()
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=2)
            policy_hmac = new_hmac

        with open('transaction.json', 'r') as f:
            trans_data = json.load(f)
        psbt_base64 = trans_data['unsigned_psbt']

        psbt = PSBT()
        psbt.deserialize(psbt_base64)

        try:
            client.get_wallet_address(policy, policy_hmac, change=0, address_index=0, display=False)
        except:
            print("HMAC validation failed. Re-registering...")
            policy_id_bytes, new_hmac = client.register_wallet(policy)
            policy_id = policy_id_bytes.hex()
            if policy_id != expected_policy_id:
                print(f"Policy ID mismatch! Got: {policy_id}, Expected: {expected_policy_id}")
                return None
            matching_key['hmac_buffer'] = new_hmac.hex()
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=2)
            policy_hmac = new_hmac

        try:
            result = client.sign_psbt(psbt, policy, policy_hmac)
            signed_data = [[input_index, partial_sig.pubkey.hex(), partial_sig.signature.hex()] for input_index, partial_sig in result]

            if 'signed_psbts' not in trans_data:
                trans_data['signed_psbts'] = {}
            if fpr in trans_data['signed_psbts']:
                print(f"Already signed with device {fpr}")
                return fpr
            trans_data['signed_psbts'][fpr] = signed_data
            with open('transaction.json', 'w') as f:
                json.dump(trans_data, f, indent=2)
            print(f"Signed with device {fpr}")
            return fpr
        except Exception as e:
            if '0xb008' in str(e):
                print("Signing failed due to invalid HMAC. Re-registering...")
                policy_id_bytes, new_hmac = client.register_wallet(policy)
                policy_id = policy_id_bytes.hex()
                if policy_id != expected_policy_id:
                    print(f"Policy ID mismatch! Got: {policy_id}, Expected: {expected_policy_id}")
                    return None
                matching_key['hmac_buffer'] = new_hmac.hex()
                with open('config.json', 'w') as f:
                    json.dump(config, f, indent=2)
                policy_hmac = new_hmac
                result = client.sign_psbt(psbt, policy, policy_hmac)
                signed_data = [[input_index, partial_sig.pubkey.hex(), partial_sig.signature.hex()] for input_index, partial_sig in result]
                if 'signed_psbts' not in trans_data:
                    trans_data['signed_psbts'] = {}
                if fpr not in trans_data['signed_psbts']:
                    trans_data['signed_psbts'][fpr] = []
                if signed_data not in trans_data['signed_psbts'][fpr]:
                    trans_data['signed_psbts'][fpr].append(signed_data)
                with open('transaction.json', 'w') as f:
                    json.dump(trans_data, f, indent=2)
                print(f"Signed with device {fpr} after re-registration")
                return fpr
            else:
                print(f"Signing failed: {str(e)}")
                return None

def load_signed_psbts():
    if not os.path.exists('transaction.json'):
        return []
    with open('transaction.json', 'r') as f:
        data = json.load(f)
    signed_psbts_data = data.get('signed_psbts', {})
    all_psbts = set()
    for psbts in signed_psbts_data.values():
        all_psbts.update(psbts)
    return list(all_psbts)

def broadcast_tx(rpc):
    rpc = connect_rpc()  # Refresh RPC connection
    print("Loading signed PSBTs...")
    with open('transaction.json', 'r') as f:
        trans_data = json.load(f)
    psbt = PSBT()
    psbt.deserialize(trans_data['unsigned_psbt'])
    for fpr in trans_data.get('signed_psbts', {}):
        sig_data = trans_data['signed_psbts'][fpr]
        if sig_data and isinstance(sig_data[0], str):
            print(f"Merging old format signatures from {fpr}")
            for signed_base64 in sig_data:
                signed_psbt = PSBT()
                signed_psbt.deserialize(signed_base64)
                for i, inp in enumerate(signed_psbt.inputs):
                    for pub, sig in inp.partial_sigs.items():
                        psbt.inputs[i].partial_sigs[pub] = sig
        else:
            print(f"Adding signatures from {fpr}")
            for idx, pub_hex, sig_hex in sig_data:
                psbt.inputs[idx].partial_sigs[bytes.fromhex(pub_hex)] = bytes.fromhex(sig_hex)
    combined_psbt = psbt.serialize()

    decoded = rpc.decodepsbt(combined_psbt)
    locktime = decoded['tx']['locktime']
    if locktime >= 500000000:
        valid_time = datetime.datetime.fromtimestamp(locktime)
        print(f"Transaction valid after: {valid_time} (Unix timestamp: {locktime})")
    else:
        print(f"Transaction valid after block height: {locktime}")

    analyzed = rpc.analyzepsbt(combined_psbt)
    print("Analyzed PSBT:", json.dumps(analyzed, indent=2, default=lambda o: float(o) if isinstance(o, decimal.Decimal) else o))

    finalized = rpc.finalizepsbt(combined_psbt)
    if finalized['complete']:
        tx_hex = finalized['hex']
        with open('final_tx.txt', 'w') as f:
            f.write(tx_hex)
        print("Saved TX HEX to final_tx.txt")
        try:
            txid = rpc.sendrawtransaction(tx_hex)
            print(f"Broadcasted TXID: {txid}")
        except JSONRPCException as e:
            print(f"Broadcast failed (possibly due to time lock): {e}")
    else:
        print("PSBT not complete. Analysis may show what's missing.")

if __name__ == "__main__":
    print("Welcome to the Recovery Wizard")

    if not validate_node_config() or not validate_config():
        print("Please update the configuration files and try again.")
        exit(1)

    print("Configuration files validated.")

    output_address = None
    fee_rate = 1
    send_to_file = 'send_to_address.txt'
    if os.path.exists(send_to_file):
        with open(send_to_file, 'r') as f:
            prev_address = f.read().strip()
        confirm = input(f"Previous send address found: {prev_address}\nDo you want to use this address? (y/n): ").lower()
        if confirm == 'y':
            output_address = prev_address
            # Skip fee rate prompt, use default 1
        else:
            print("Warning: Changing the address will restart the process.")
            output_address = input("Enter the new Bitcoin address to send funds to: ")
            fee_rate_str = input("Enter the fee rate (sat/vbyte, default 1): ") or "1"
            fee_rate = int(fee_rate_str)
            if os.path.exists('transaction.json'):
                os.remove('transaction.json')
                print("Deleted existing transaction.json to start new.")
    else:
        output_address = input("Enter the Bitcoin address to send funds to: ")
        fee_rate_str = input("Enter the fee rate (sat/vbyte, default 1): ") or "1"
        fee_rate = int(fee_rate_str)

    # Write the address to file
    with open(send_to_file, 'w') as f:
        f.write(output_address)

    rpc = connect_rpc()

    trans_data = {}
    if os.path.exists('transaction.json'):
        with open('transaction.json', 'r') as f:
            trans_data = json.load(f)

    if 'unsigned_psbt' not in trans_data:
        psbt = create_psbt(rpc, output_address, fee_rate)
        if psbt:
            trans_data['unsigned_psbt'] = psbt
            trans_data['signed_psbts'] = trans_data.get('signed_psbts', {})
            with open('transaction.json', 'w') as f:
                json.dump(trans_data, f, indent=2)
            print("PSBT created and saved to transaction.json")
        else:
            print("Failed to create PSBT.")
            exit(1)
    else:
        print("Existing unsigned PSBT found, skipping creation.")

    signed_fprs = set(trans_data.get('signed_psbts', {}).keys())
    if len(signed_fprs) >= 2:
        print("Two or more unique signatures already collected. Proceeding to broadcast.")
    else:
        while len(signed_fprs) < 2:
            input("Connect a Ledger device and press Enter to sign...")
            fpr = sign_with_ledger()
            if fpr and fpr not in signed_fprs:
                signed_fprs.add(fpr)
                print(f"Signed with {len(signed_fprs)} unique devices.")
                # Reload trans_data after signing
                with open('transaction.json', 'r') as f:
                    trans_data = json.load(f)
            else:
                print("Signing failed or device already used. Try again.")

    broadcast_tx(rpc)
    print("You can view the final transaction in final_tx.txt")
