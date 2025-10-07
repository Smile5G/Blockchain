import socket
import threading
import json
import random
import base64
from independent_functions import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from decimal import Decimal
import time
#------ Node ------
class NodeState:
    def __init__(self):
        # Chain-Kontext (z. B. aktuelle Blockchain, Validierungsstatus, etc.)
        self.chain_context = []

        # Transaktionspuffer zur Vermeidung von Dopplungen
        self.trans_buffer = []

        # Alle möglichen Chains aus dem aktuellen Kontext
        self.all_chains = []
        # current nonce
        self.nonce = 0
        # Die aktuell stärkste bekannte Chain
        self.strongest_chain = []

        # Aktive Peer-Sockets
        self.all_peers = []
        # seen nonces 
        self.all_nonces = dict()
        # balances 
        self.balances = []
        # Bekannte Peer-Adressen mit Ratings
        self.known_addresses = []
        # new block
        self.new_block = False

        # Lock für Thread-Sicherheit
        self.lock = threading.Lock()
    def add_new_adress(self, adress):
        with self.lock:
            if adress not in self.known_addresses:
                self.known_addresses.append({"addr": adress, "rating": 5, "timestemp": 0})
    def update_new_block(self):
        if self.new_block:
            self.new_block = False
        else:
            self.new_block = True
    def get_new_block(self):
        return self.new_block
    def fill_all_nonces(self, nonces):
        with self.lock:
            self.all_nonces = nonces
    def add_nonce_dic(self, nonce):
        with self.lock:
            self.all_nonces.append(nonce)
    def update_own_nonce(self, public_key):
        with self.lock:
            nonces = self.all_nonces.get(public_key)
            if nonces == None:
                self.nonce = 0 
                return
            self.nonce = max(nonces)
    def sync_own_nonce(self):
        with self.lock:
            self.nonce+=1
    def get_nonce(self):
        return self.nonce

    def add_balance_dix(self, balances):
        with self.lock:
            self.balances.append(balances)
    def update_nonce(self, public_key, nonce):
        with self.lock:
            nonces = self.all_nonces.get(public_key)
            if nonces == None:
                nonces = []
            nonces.append(nonce)
            self.all_nonces[public_key]= nonces
    def check_nonce(self, nonce, public_key):
        with self.lock:
            nonces = self.all_nonces.get(public_key)
            if nonces is None:
                return False
            if nonce in nonces:
                return True
            return False
    def get_balance(self, public_key, chains_number):
        with self.lock:
            try:
                balance = self.balances[chains_number].get(f"{public_key}")
                if balance == None:
                    return 0
                return balance
            except (IndexError, AttributeError):
                return 0
    def update_balance(self, public_key, sum, chains_number):
        with self.lock:
            try:
                self.balances[chains_number][f"{public_key}"] = (
                    Decimal(self.balances[chains_number].get(public_key) or 0)
                    + Decimal(sum)
                )
            except (IndexError, AttributeError):
                return 0
    
    def fill_all_balances(self, balances):
        with self.lock:
            self.balances = balances

    def get_peers(self):
        """Gibt eine Kopie der aktiven Peer-Sockets zurück."""
        with self.lock:
            return list(self.all_peers)

    def update_peers(self, peers):
        """Aktualisiert die Liste der aktiven Peer-Sockets."""
        with self.lock:
            self.all_peers = peers

    def get_known_addresses(self):
        """Gibt eine Kopie der bekannten Peer-Adressen zurück."""
        with self.lock:
            return list(self.known_addresses)

    def update_known_addresses(self, addresses):
        """Aktualisiert die Liste der bekannten Peer-Adressen."""
        with self.lock:
            self.known_addresses = addresses

    def deduct_peers(self, bad_ips):
        """Zieht für gegebene IPs jeweils einen Rating-Punkt ab."""
        with self.lock:
            for bad_ip in bad_ips:
                for entry in self.known_addresses:
                    if entry.get("address") == bad_ip:
                        entry["rating"] = entry.get("rating", 0) - 1
    def add_timestemp_to_peer(self, peer):
        with self.lock:
            for adresses in self.known_addresses:
                if adresses.get("addr") == peer:
                    adresses["timestemp"] = time.time()

    def safe_append_trans(self, tx_sig):
        """adds a transaction to the buffer ."""
        with self.lock:
            self.trans_buffer.append(tx_sig)

    def get_chain_context(self):
        """Gibt das aktuelle Chain-Context-Array zurück."""
        with self.lock:
            return list(self.chain_context)

    def update_chain_context(self, new_context):
        """Ersetzt das Chain-Context-Array."""
        with self.lock:
            self.chain_context = new_context

    def get_trans_buffer(self):
        """Gibt eine Kopie des Transaktions-Puffers zurück."""
        with self.lock:
            return list(self.trans_buffer)

    def update_trans_buffer(self, buffer):
        """Ersetzt den Transaktions-Puffer."""
        with self.lock:
            self.trans_buffer = buffer
    def add_to_trans(self, transaction):
        with self.lock:
            self.trans_buffer.append(transaction)

    def get_strongest_chain(self):
        """Gibt die aktuell stärkste Chain zurück."""
        with self.lock:
            return list(self.strongest_chain)

    def update_strongest_chain(self):
        """updates strogest chain """
        with self.lock:
            self.strongest_chain = get_strongest_chain(self.all_chains)
    def update_all_types_of_chains(self):
        with self.lock:
            self.all_chains = extract_all_chains(chain_content=self.chain_context)
            self.strongest_chain = get_strongest_chain(self.all_chains)
    def get_index_of_chain(self):
        with self.lock:
            return int(self.strongest_chain[-1]["index"])
    def finish_peers(self):
        for adrees in self.known_addresses:
            adrees["timestemp"] = int(time.time())
    def get_all_chains(self):
        return self.all_chains
    def check_if_block_chain_end(self, block):
        for idx ,i in enumerate(self.all_chains):
            if i[-1].get("hash") == block.get("previous_hash"):
                return True, idx
        return False, len(self.all_chains)
    def get_chain(self, block):
        with self.lock:
            chain = []
            current_hash = block.get("hash")
            while True:
                for b in self.chain_context:
                    if b.get("hash") == current_hash:
                        chain.append(b)
                        current_hash = b.get("previous_hash")
                        break
                else:
                    break
            return list(reversed(chain))
    def get_chain_with_number(self, chain_number):
        return self.all_chains[chain_number]
    def add_chain(self, chain):
        self.all_chains.add(chain)
    def add_to_chain(self, chain_number, block):
        with self.lock:
            self.all_chains[chain_number].append(block)
    def get_chain_number_of_strongest_chain(self):
        with self.lock:
            return self.all_chains.index(self.strongest_chain)

# === Server Thread ===
def handle_client(conn):
    try:
        raw_length = conn.recv(4)
        if not raw_length:
            return None
        msg_length = int.from_bytes(raw_length, byteorder='big')

        data = b''
        while len(data) < msg_length:
            packet = conn.recv(msg_length - len(data))
            if not packet:
                return None
            data += packet

        msg = json.loads(data.decode())
        return msg
    except:
        return None




# === Connect to known peer ===
def connect_to_peer(ip, port):
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        peer.connect((ip, port))
        print(f"[+] Connected to {ip}:{port}")
        return peer, True
    except Exception as e:
        print(f"[!] Failed to connect to {ip}:{port} - {e}")
        return peer, False

#extrack all peers
def load_peers(path):
    with open(path, "r") as file:
        return json.load(file)

def get_peers(number_of_peers, peers):
    sorted_peers = sorted(peers, key=lambda p: p.get("rating", 0), reverse=True)
    best_peers = sorted_peers[:number_of_peers]
    sorted_peers.remove(i for i in best_peers)
    return best_peers, sorted_peers

def get_headers(index, peer):
    try:
        message = {
            "type": "get_headers",
            "index": index
        }
        json_data = json.dumps(message).encode()
        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"[!] Failed to send get_headers: {e}")
def get_blocks(index, peer):
    try:
        message = {
            "type": "get_blocks",
            "index": index
        }
        json_data = json.dumps(message).encode()
        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"[!] Failed to send get_blocks: {e}")
            
def send_blocks_to_peer(blocks, peer, current_index):
    message = {
        "type": "blocks",
        "blocks": blocks,
        "current_index": current_index
    }

    try:
        json_data = json.dumps(message).encode()
        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"[!] Failed to send blocks: {e}")

def send_headers_to_peer(headers, peer):
    message = {
        "type": "headers",
        "headers": headers
    }
    try:
        json_data = json.dumps(message).encode()

        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"[!] Failed to send headers: {e}")
    
def send_block(block, peer):
    message = {
        "type": "blocks",
        "content": block
    }
    try:
        json_data = json.dumps(message).encode()
        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"failed to transmit block")
def send_transaction(tx, peer):
    message = {
        "type": "transactions",
        "content": tx
    }
    try:
        json_data = json.dumps(message).encode()
        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"failed to transmit transaction ")

def stronger_chain_found(chain, peers):
    message = {
        "type": "stronger_chain_found",
        "blocks": chain
    }
    json_data = json.dumps(message).encode()
    length = len(json_data).to_bytes(4, byteorder='big')
    for peer in peers:
        try:
            peer.sendall(length + json_data)
        except Exception as e:
            print(f"Failed to send strongest chain")
def send_sync_finished(peer):
    message = {"type": "syncing finished", "message": "Thank you for the blocks"}
    try:
        json_data = json.dumps(message).encode()
        length = len(json_data).to_bytes(4, byteorder='big')
        peer.sendall(length + json_data)
    except Exception as e:
        print(f"[!] Failed to send sync finished message: {e}")
def listen_for_headers(peer):
    try:
        while True:
            raw_length = peer.recv(4)
            if not raw_length:
                break
            msg_length = int.from_bytes(raw_length, byteorder='big')

            data = b''
            while len(data) < msg_length:
                packet = peer.recv(msg_length - len(data))
                if not packet:
                    break
                data += packet

            message = json.loads(data.decode())
            if message.get("type") == "headers":
                return  message.get("content")
                
    except Exception as e:
        print(f"[!] Listening error: {e}")
def listen_for_blocks(peer, index):
    import hashlib
    entire_chain = []
    try:
        while True:
            raw_length = peer.recv(4)
            if not raw_length:
                break
            msg_length = int.from_bytes(raw_length, byteorder='big')

            data = b''
            while len(data) < msg_length:
                packet = peer.recv(msg_length - len(data))
                if not packet:
                    break
                data += packet

            message = json.loads(data.decode())

            # === Signature Verification ===
            try:
                signature = base64.b64decode(message.get("signature", ""))
                public_key_pem = message.get("public_key")
                if public_key_pem:
                    public_key = serialization.load_pem_public_key(public_key_pem.encode())
                    message_copy = dict(message)
                    if "signature" in message_copy:
                        del message_copy["signature"]
                    json_data_unsigned = json.dumps(message_copy).encode()
                    public_key.verify(
                        signature,
                        json_data_unsigned,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                else:
                    print("[!] Missing public key for signature verification.")
                    continue
            except Exception as e:
                print(f"[!] Signature verification failed: {e}")
                continue

            if message.get("type") == "blocks":
                blocks = message.get("content")
                for block in blocks:
                    block_str = json.dumps(block, sort_keys=True).encode()
                    block_hash = hashlib.sha256(block_str).hexdigest()
                    if block_hash != block.get("hash"):
                        print(f"[!] Hash mismatch for block with index {block.get('index')}")
                        continue
                    entire_chain.append(block)

                # Check if last block index matches the expected current_index from message
                if index == message.get("current_index"):
                    return entire_chain
    except Exception as e:
        print(f"[!] Listening error: {e}")


from blockchain import *
def check_incoming_messages(node:NodeState, chain_file_path, block_package_size, peer, sync_buffer, syncing):
    peers = node.get_peers()
    if peer in peers:
        peers.remove(peer)
    message = handle_client(peer)
    strongest_chain = node.get_strongest_chain()
    # chain_context = node.get_chain_context()  # Removed as per instruction
    trans_buffer = node.get_trans_buffer()
    if message.get("type") == "blocks":
        status = adding_new_block(
            node=node,
            block=message.get("content"),
            block_file_path=chain_file_path
        )
        if strongest_chain[-1].get("hash") == message["content"]["previous_hash"]:
            node.update_new_block()
        if status:
            for p in peers:
                send_block(peer=p, block=message.get("content"))

    elif message.get("type") == "transactions":
        tx = message.get("content")
        sig = (tx.get("senders_public_id"), tx.get("nonce"))
        if sig not in trans_buffer:
            for p in peers:
                send_transaction(peer=p, tx=tx)
            trans_buffer.append(sig)
            node.update_trans_buffer(trans_buffer)

    elif message.get("type") == "get_headers":
        idx = message.get("index")
        if 0 <= idx < len(strongest_chain):
            headers = strongest_chain[idx:]
        else:
            headers = []
        send_headers_to_peer(peer=peer, headers=headers)
    elif message.get("type") == "get_blocks":
        idx = message.get("index")
        block_packages = get_full_block_packages(
            node=node,
            block_file_path=chain_file_path,
            idx=idx,
            package_size=block_package_size
        )
        for package in block_packages:
            current_idx = package[-1]["index"]
            send_blocks_to_peer(
                blocks=package,
                peer=peer,
                current_index=current_idx
            )
            time.sleep(3)


    elif message.get("type") == "syncing_finished":
        for obj in sync_buffer:
            if obj.get("type") == "blocks":
                send_block(peer=peer, block=obj)
                time.sleep(3)
        syncing = False
    if syncing and message.get("type") in ("blocks", "transactions"):
        sync_buffer.append(message.get("content"))

    return  sync_buffer, syncing


def start_peer_thread(peer, node: NodeState, block_package_size, chain_file_path):
    syncing = True
    sync_buffer = []
    try:
        while True:
            active_peers = node.get_peers()

            sync_buffer, syncing = check_incoming_messages(
                node=node,
                chain_file_path=chain_file_path,
                block_package_size=block_package_size,
                peer=peer,
                sync_buffer=sync_buffer,
                syncing=syncing
            )



            time.sleep(1)

    except Exception as e:
        print(f"Fehler mit Peer {peer}: {e}")
        active_peers = node.get_peers()
        if peer in active_peers:
            active_peers.remove(peer)
            node.update_peers(active_peers)
    finally:
        peer_ip, _ = peer.getpeername()
        node.add_timestemp_to_peer(peer_ip)
        peer.close()


            
def start_server(port: int, node: NodeState):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen()

    while True:
        conn, addr = server.accept()           # addr ist (ip, port)
        peer_ip, peer_port = addr
        node.add_new_adress(peer_ip)
        # 1) Socket in NodeState aufnehmen
        peers = node.get_peers()
        peers.append(conn)
        node.update_peers(peers)

        # 2) Starte Deinen Peer-Handler in einem Daemon-Thread
        thread = threading.Thread(
            target=start_peer_thread,
            args=(conn, node),     
            daemon=True
        )
        thread.start()
 