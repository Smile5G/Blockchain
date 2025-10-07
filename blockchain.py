import json
from decimal import Decimal
def convert_decimal(obj):
    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return float(obj)
    else:
        return obj
import os
from collections import defaultdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
import time
import ijson
from copy import deepcopy
import tempfile
import bisect
from independent_functions import *
from Network import NodeState, send_block
from multiprocessing import Queue, Process, Value, Lock
import queue
def get_balances_and_nonces(node: NodeState, chain_path):
    chain_balances = []
    from collections import defaultdict
    combined_nonces = defaultdict(list)

    with open(chain_path, "r") as file:
        all_blocks = list(ijson.items(file, 'item'))

    # combined_nonces is initialized here to aggregate across all chains
    for chain in node.get_all_chains():
        balances = defaultdict(int)
        hashes_set = set(block["hash"] for block in chain)

        for block in all_blocks:
            block_hash = block.get("hash")
            if block_hash in hashes_set:
                for tx in block.get("transactions", []):
                    sender = tx.get("sender_public_key")
                    recipient = tx.get("recipient_public_key")
                    amount = tx.get("amount", 0)
                    fee = tx.get("fee", 0)

                    if sender:
                        balances[sender] -= (amount + fee)
                        # Append each nonce to the sender's list, globally
                        combined_nonces[sender].append(tx.get("nonce", 0))

                    if recipient:
                        balances[recipient] += amount

                reward_recipient = block.get("reward_recipient")
                reward = block.get("block_reward", 0)
                if reward_recipient:
                    balances[reward_recipient] += reward
        
        chain_balances.append(dict(balances))

    node.fill_all_balances(chain_balances)
    node.fill_all_nonces(dict(combined_nonces))

# New function: get_balances_and_nonces_for_chain
def get_balances_and_nonces_for_chain(node: NodeState, chain, chain_path):
    balances = defaultdict(int)

    with open(chain_path, "r") as file:
        all_blocks = list(ijson.items(file, 'item'))

    hashes_set = set(block["hash"] for block in chain)

    for block in all_blocks:
        block_hash = block.get("hash")
        if block_hash in hashes_set:
            for tx in block.get("transactions", []):
                sender = tx.get("sender_public_key")
                recipient = tx.get("recipient_public_key")
                amount = tx.get("amount", 0)
                fee = tx.get("fee", 0)

                if sender:
                    balances[sender] -= (amount + fee)

                if recipient:
                    balances[recipient] += amount

            reward_recipient = block.get("reward_recipient")
            reward = block.get("block_reward", 0)
            if reward_recipient:
                balances[reward_recipient] += reward

    node.add_balance_dix(dict(balances))
    
def get_coins_public_id(public_id, node:NodeState):
    return node.get_balance(public_key=public_id)
    

# Verifies a digital signature given a public key, message, and base64 encoded signature
def verify_signature(public_key_pem, message: str, signature_b64: str) -> bool:
    try:
        if "BEGIN PUBLIC KEY" not in public_key_pem:
            public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key_pem}\n-----END PUBLIC KEY-----"
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Signature error:", e)
        return False

# Verifies a single transaction's validity including signature, nonce uniqueness, and balances
def verify_single_transaction(tx,node:NodeState,chain_number ):
    sender = tx.get("sender_public_key")
    recipient = tx.get("recipient_public_key")
    nonce = tx.get("nonce", 0)
    signature = tx.get("signature")
    fee = tx.get("fee", 0)
    amount = tx.get("amount", 0)

    message = f"{sender}{recipient}{amount}{fee}{nonce}"
    print(message)
    if not verify_signature(sender, message, signature):
        return False, fee, 1
    if node.check_nonce(nonce=nonce, public_key=sender):
        return False, fee, 2 
    if not ((node.get_balance(sender, chains_number=chain_number))> amount+fee):
        return False, fee, 3
    return True, fee, 4

# Verifies all transactions within a block for validity
def verify_all_transactions_in_block(block, chain_number, node:NodeState):
    # Check for cumulative overspending before individual verification
    if not verify_cumulative_spending(block.get("transactions", []), node, chain_number):
        print("Cumulative overspending detected")
        return False, 0
    sum_fee = 0
    for tx in block.get("transactions", []):
        print(tx)
        verification , fee, sybol  = verify_single_transaction(tx, node=node, chain_number=chain_number)
        if sybol > 1:
            node.update_nonce(public_key=tx.get("sender_public_key"), nonce=tx.get("nonce"))
        if not verification:
            return False, 0 
        sum_fee+=fee
    return True, sum_fee
# verify hash 
def verify_hash(block):
    print(block.get("hash"))
    if block.get("hash") == calculate_hash(block):
        return True
    else:
        return False
    
# Checks if the previous_hash of a block matches the hash of the previous block
def check_hashes(block, privious):
    if block["previous_hash"] == privious["hash"]:
        return True
    else:
        return False

# Checks if a block's hash meets the difficulty target
def check_difficulty(block, chain):
    target_value = estimate_target_values(chain= chain,check_index=block.get("index", 0) )
    hash_number = int(block.get("hash"), 16)
    if hash_number <= target_value:
        return True
    else:
        return False
# Validates that the block reward is correct based on halving schedule
def calculate_block_reward(block, initial_reward=57, halving_interval=877193):
    halvings = block.get("index", 0) // halving_interval
    current_reward = initial_reward / (2 ** halvings)
    if block.get("block_reward", 0) <= current_reward:
        return True 
    else: 
        return False
def calculate_reward(index, initial_reward=57, halving_interval=877193):
    halvings = index // halving_interval
    current_reward = initial_reward / (2 ** halvings)
    return current_reward
# Verifies all aspects of a block including transactions, hashes, difficulty, and reward
def verify_blocks(block, chain_number,attendence, node:NodeState, chain_path):
    if not attendence:
        chain = node.get_chain(block=block)
        get_balances_and_nonces_for_chain(node=node, chain=chain, chain_path=chain_path)
    else:
        chain = node.get_chain_with_number(chain_number)
    verification, fee = verify_all_transactions_in_block(block, chain_number= chain_number, node = node)
    if not verification:
        print("tansactions_verified")
        return False, 0
    if not check_difficulty(block, chain):
        print("difficulty verified")
        return False, 0
    if not calculate_block_reward(block=block):
        print("reward_ verfied")
        return False, 0
    if not verify_hash(block):
        print("hash_verified")
        return False, 0 
    return True, fee

#----------------------------------------------------
#check if block header fits any any part of the privious chain:
def check_block_header(header, context):
    previous = header.get("previous_hash")
    for i in context:
        if previous == i.get("header"):
            return True
    return False

# New function to get full block packages
# Retrieves full blocks in packages from the chain starting at a given index
def get_full_block_packages(node: NodeState, block_file_path: str, idx: int, package_size: int):
    chains = extract_all_chains(load_chain(block_file_path))
    strongest_chain = get_strongest_chain(chains)
    target_hashes = set(block["hash"] for block in strongest_chain[idx:])

    packages = []
    current_package = []

    with open(block_file_path, 'r') as f:
        for block in ijson.items(f, 'item'):
            block_hash = block.get("hash")
            if block_hash in target_hashes:
                current_package.append(block)
                if len(current_package) == package_size:
                    packages.append(current_package)
                    current_package = []
                target_hashes.remove(block_hash)
                if not target_hashes:
                    break

    if current_package:
        packages.append(current_package)

    return packages
# Adds a timestamp to a received block
def add_timestempt(recieved_block):
    block = recieved_block
    block["timestemp"] = int(time.time())
    return block
# Adds a new block to the context if it links correctly and passes verification

def adding_new_block(block, node: NodeState, block_file_path: str) -> bool:
    """
    Fügt einen neuen Block speichereffizient in die Blockchain-Datei
    und aktualisiert nur die notwendigen Header.
    """
    # 1) Timestamp ergänzen
    if block.get("timestemp")== 0:
        block = add_timestempt(block)
    # 2) Lokalen Header-Kontext (sortiert) holen
    context = node.get_chain_context()
    indices = [hdr["index"] for hdr in context]

    # 3) Einfügeposition bestimmen (binäre Suche)
    pos = bisect.bisect_left(indices, block["index"])
    # 4) Duplicate-Check
    if pos < len(indices) and indices[pos] == block["index"]:
        return False

    # 5) Prüfen, dass prev_hash im Kontext existiert
    header_map = {hdr["hash"]: hdr for hdr in context}
    prev_hdr = header_map.get(block.get("previous_hash"))
    if not prev_hdr:
        return False

    # 6) Minimalen Chain-Teil für die Verifikation aufbauen

    # 7) Vollblöcke aus Datei streamen
    
#------------------------------
    # 8) Verifikation
    attendence, chain_number = node.check_if_block_chain_end(block=block)
    verification, fee = verify_blocks(block=block,chain_number=chain_number, attendence=attendence, node=node, chain_path=block_file_path)
    if not verification:
        return False
    node.update_balance(public_key=block.get("reward_recipient"), chains_number=chain_number, sum=fee+block.get("block_reward", 0))
    for tx in block.get("transactions"):
        node.update_balance(public_key=tx.get("sender_public_key"), chains_number=chain_number,sum = -(tx.get("amount", 0)+tx.get("fee", 0)))
        node.update_balance(public_key=tx.get("recipient_public_key"), chains_number=chain_number, sum= tx.get("amount", 0))
#-----------------------------
    # 9) Stream-basiertes Einfügen in die Datei
    inserted = False
    with open(block_file_path, "r", encoding="utf-8") as src, \
         tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        tmp.write("[")
        first = True
        for blk in ijson.items(src, "item"):
            if not inserted and blk["index"] > block["index"]:
                if not first:
                    tmp.write(",\n")
                tmp.write(json.dumps(convert_decimal(block)))
                first = False
                inserted = True

            if not first:
                tmp.write(",\n")
            tmp.write(json.dumps(convert_decimal(blk)))
            first = False

        if not inserted:
            if not first:
                tmp.write(",\n")
            tmp.write(json.dumps(convert_decimal(block)))
        tmp.write("\n]")

    os.replace(tmp.name, block_file_path)
    # 10) Header-Kontext aktualisieren (einfach einfügen statt sortieren)
    header = {
        "hash":          block["hash"],
        "previous_hash": block["previous_hash"],
        "index":         block["index"],
        "timestemp":     block["timestemp"]
    }
    context.insert(pos, header)
    node.update_chain_context(context)
    node.add_to_chain(chain_number=chain_number, block=header)
    # 11) Transaktions-Puffer bereinigen
    buffer = node.get_trans_buffer()
    for tx in block.get("transactions", []):
        sig = (tx.get("sender_public_id"), tx.get("nonce"))
        if sig in buffer:
            buffer.remove(sig)
    node.update_trans_buffer(buffer)

    # 12) Stärkste Chain neu berechnen und evt. balances aktualisieren
    node.update_strongest_chain()
    return True



# Returns the index of the last block in the context
def get_index(context):
    index = context[-1]["index"]
    return index

# Verifies the consistency of a sequence of block headers by checking hash links
def check_new_chain_headers(chain_headers):
    """
    Verifies consistency of a sequence of block headers (index, hash, previous_hash).
    Checks that each block's previous_hash matches the hash of the previous block.
    """
    if len(chain_headers) < 2:
        return True  
    for i in range(len(chain_headers) - 1, 0, -1):
        current = chain_headers[i]
        previous = chain_headers[i - 1]
        if current["previous_hash"] != previous["hash"]:
            return False
    return True

# New function to check full block chains
# Verifies consistency and validity of a sequence of full blocks
def check_new_chain_blocks(chain_blocks):
    """
    Verifies consistency and validity of a sequence of full blocks.
    Applies full verification including hashes, difficulty, transactions, and reward.
    """
    if len(chain_blocks) < 2:
        return True

    for i in range(len(chain_blocks) - 1, 0, -1):
        current = chain_blocks[i]
        previous = chain_blocks[i - 1]
        if not verify_blocks(current, previous, chain_blocks[:i]):
            return False
    return True
def check_headers_and_blocks(chain, hashes):
    for idx, block in enumerate(chain):
        if not(block.get("hash") == hashes[idx].get("hash") and block.get("previous_hash") == hashes[idx].get("previous_hash")):
            return False
    return True
#returns the entire chain of a new addad block
def get_verification_and_strength_of_chain(chain, chains):
    correct_chain = []
    for chainer in chains:
        for idx, block in enumerate(chainer):
            if block.get("hash")== chain[0].get("previous_hash"):
                correct_chain.append(chainer + chain)
    correct_chain = correct_chain(set(correct_chain))
    correct_chain.sort(key=lambda block: block["index"])
    verifciation = check_new_chain_blocks(correct_chain)
    return verifciation, correct_chain

def insert_blocks_sorted(new_blocks, path):
    existing_blocks = []
    existing_hashes = set()

    # Alte Blöcke iterativ lesen
    with open(path, 'r') as f:
        for block in ijson.items(f, 'item'):
            existing_blocks.append(block)
            existing_hashes.add(block["hash"])

    # Nur neue Blöcke (per Hash)
    filtered_new = [b for b in new_blocks if b["hash"] not in existing_hashes]

    # Kombinieren und sortieren
    combined = existing_blocks + filtered_new
    combined.sort(key=lambda b: b["index"])

    # Datei vollständig überschreiben
    with open(path, 'w') as f:
        json.dump(combined, f, indent=4)

# sign transactions
def sign_transaction(private_key_pem: str, sender: str, recipient: str, amount: int, fee: int, nonce: int) -> str:
    """
    Signiert eine Transaktion mit einem privaten PEM-Schlüssel.
    Gibt die Signatur als Base64-codierten String zurück.
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

    message = f"{sender}{recipient}{amount}{fee}{nonce}"
    print(message)
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()
# mining functions
def mine(node:NodeState, chain_path, public_key):
    while True:
        trans_buffer = node.get_trans_buffer()
        peers = node.get_peers()
        strongest_chain = node.get_strongest_chain()
        index = node.get_index_of_chain() + 1
        target_value = estimate_target_values(chain=strongest_chain, check_index=index)
        previous_hash = strongest_chain[-1].get("hash")
        nonce = 0
        block_reward = calculate_reward(index=index)
        transactions = []
        # Sort transactions by descending fee
        trans_buffer.sort(key=lambda tx: tx.get("fee", 0), reverse=True)
        # Filter out duplicate transactions based on (sender, nonce)
        seen = set()
        filtered_buffer = []
        for tx in trans_buffer:
            key = (tx.get("sender_public_key"), tx.get("nonce"))
            if key not in seen:
                seen.add(key)
                filtered_buffer.append(tx)
        trans_buffer = filtered_buffer
        # Track cumulative spending to avoid overspending in total
        cumulative_spending = defaultdict(int)
        current_balances = {}
        chain_number = node.get_chain_number_of_strongest_chain()
        already = []
        for tx in trans_buffer:
            sender = tx.get("sender_public_key")
            if sender not in current_balances:
                current_balances[sender] = node.get_balance(sender, chains_number=chain_number)
        # Main mining transaction selection loop with cumulative spending per sender
        for tx in trans_buffer:
            sender = tx.get("sender_public_key")
            already.append(sender)
            if len(transactions) >= 2015:
                break
            fee = tx.get("fee", 0)
            amount = tx.get("amount", 0)
            total_spending = cumulative_spending[sender] + amount + fee
            if total_spending > current_balances.get(sender, 0):
                continue  # Overspending within the block
            valid, _ , _= verify_single_transaction(tx, node=node, chain_number=chain_number)
            if valid:
                transactions.append(tx)
                cumulative_spending[sender] = total_spending
        print(transactions)
        # PEM bereinigen
        pem_str = public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
        # Block-Daten vorbereiten
        block = {
            "index": index,
            "previous_hash": previous_hash,
            "transactions": transactions,
            "nonce": nonce,
            "timestemp": 0,
            "block_reward": block_reward,
            "reward_recipient": pem_str,
            "hash": ""
        }
        # Mining-Schleife
        stop_flag = Value("b", False)
        q = Queue()
        m = Queue()
        p = Process(target=find_a_valid_hash, args=(block, target_value, stop_flag, q, m))
        p.start()
        counter = 0
        while p.is_alive():
            if node.get_new_block():
                stop_flag.value = True
                p.terminate()
                p.join()
                return
            counter += 1
            time.sleep(0.1)

        # Nach Mining Ergebnis prüfen
        if q.empty():
            continue  # Kein gültiger Block gefunden
        success, block = q.get()
        if not success:
            continue
        print("block_found")
        print(block)
        # Block zur Blockchain hinzufügen
        verfication = adding_new_block(block, node=node, block_file_path=chain_path)
        if verfication:
            for peer in peers:
                send_block(block=block, peer=peer)
        time.sleep(30)

def calculate_hash(data: dict) -> str:
    if isinstance(data, str):
        data_dict = json.loads(data)
    elif isinstance(data, dict):
        data_dict = dict(data)
    else:
        raise ValueError("Unsupported data type for hashing")
    data_dict.pop("timestemp", None)
    data_dict.pop("hash", None)
    data_str = json.dumps(data_dict, sort_keys=True)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_str.encode())
    return digest.finalize().hex()


# Der Lock wird genutzt, um paralleles Mining zu verhindern
def find_a_valid_hash(block, target_value, stop_flag, q, m):
    start = int(time.time())
    nonce = 0
    while True:
        block["nonce"] = nonce
        block_str = json.dumps(block, sort_keys=True)
        block_hash = calculate_hash(block_str)
        block["hash"] = block_hash
        if stop_flag.value:
            q.put((False, {}))
            return
        if int(block_hash, 16) <= target_value:
            print("Valid Block found", flush=True)
            q.put((True, block))
            return

        nonce += 1
        if nonce % 10000000 == 0:
            average_hashrate = nonce/(int(time.time())- start)
            start = int(time.time())
            print(average_hashrate, flush=True)
    
# Helper function to check cumulative spending per sender in a block's transactions
def verify_cumulative_spending(transactions, node: NodeState, chain_number: int) -> bool:
    cumulative_spending = defaultdict(int)
    balances = defaultdict(int)

    # Prepare balances for all senders
    for tx in transactions:
        sender = tx.get("sender_public_key")
        if sender not in balances:
            balances[sender] = node.get_balance(sender, chains_number=chain_number)

    # Sum up spending
    for tx in transactions:
        sender = tx.get("sender_public_key")
        fee = tx.get("fee", 0)
        amount = tx.get("amount", 0)
        cumulative_spending[sender] += amount + fee

    # Compare to balances
    for sender, total in cumulative_spending.items():
        if total > balances.get(sender, 0):
            return False
    return True