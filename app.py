# === Standard Library Imports ===
import os
import json
import time
import socket
import threading
import random
from multiprocessing import process, Lock, Queue
import multiprocessing
from collections import defaultdict
# === Third-Party Library Imports ===
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import ijson
import base64
# === Local Imports ===
from blockchain import *
from Network import *
from independent_functions import *
#general programs

def load_key(filepath):
    with open(filepath, "rb") as key_file:
        return key_file.read().decode("utf-8")
def save_peers(peers, path):
    with open(path, "w") as f:
        json.dump(peers, f, indent=4)

# general programs
with open("config.json", "r") as file:
    params = json.load(file)
syncing_active = True
buffer_lock = threading.Lock()
privat_key = load_key(filepath="private_key.pem")
public_key = load_key(filepath="public_key.pem")
standart_port          = int(params["standart_port"])
max_connection_number  = int(params["max_connection_number"])
block_package_size     = int(params["block_package_size"])
current_nonce          = int(params["transaction_nonce"])
pem_str = public_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
#path variables
chain_path = params["chain_path"]
peer_path = params["peers_path"]
chain_package = load_chain(chain_path)
adresses =sorted(load_peers(peer_path), key=lambda p: (p["addr"]))
#initialising node
saving_node = NodeState()
saving_node.update_chain_context(chain_package)
saving_node.update_all_types_of_chains()
saving_node.update_known_addresses(adresses)
get_balances_and_nonces(node=saving_node, chain_path=chain_path)
saving_node.update_own_nonce(public_key=pem_str)
saving_node.sync_own_nonce()
#startu
def sync(node:NodeState, standard_port, peers_number, chain_path):
    global block_package_size, syncing_active
    strongest_chain = node.get_strongest_chain()
    chain_package = node.get_chain_context()
    chains = node.get_all_chains()
    adresses = node.get_known_addresses()
    syncing_active = True
    used_addresses = set()
    start_syncing = int(time.time())

    while True:
        # 1) Filtere diejenigen Adressen heraus, die bereits fehlten
        available = [a for a in adresses if a["addr"] not in used_addresses]
        if not available:
            print("[!] Keine Adressen mehr – Synchronisation abgebrochen.")
            break

        # 2) Baue Verbindungen zu bis zu peers_number Peers auf
        active_peers = []
        for addr in available:
            if len(active_peers) >= peers_number:
                break
            ip = addr["addr"]
            try:
                sock = socket.create_connection((ip, standard_port), timeout=1)
                sock.close()
                peer_sock, ok = connect_to_peer(ip, standard_port)
                if ok:
                    active_peers.append((peer_sock, ip))
            except:
                continue

        if not active_peers:
            if int(time.time())- start_syncing > 10:
                return chain_package, [], []
            print("[!] Keine Peers erreichbar. Neuer Versuch in 5 Sekunden…")
            time.sleep(5)
            continue

        # 3) Header-Phase: prüfen, welche Peers überhaupt passende Header liefern
        header_valid = []
        idx = get_index(chain_package)
        for peer, ip in active_peers:
            for _ in range(8):
                get_headers(idx, peer)
                headers = listen_for_headers(peer) or []
                if len(headers) < 1:
                    used_addresses.add(ip)
                    peer.close()
                    break
                if headers and check_new_chain_headers(headers) and check_block_header(headers[0], chain_package):
                    header_valid.append((peer, ip, headers, idx))
                    break
                idx = max(idx // 2, 1)
            else:
                # dieser Peer liefert keine brauchbaren Header → merken und schließen
                used_addresses.add(ip)
                peer.close()

        if not header_valid:
            print("[!] Keine gültigen Header – retry.")
            continue

        # 4) Block-Phase: lade Blocks bei header-validen Peers und verifiziere sie
        peer_chains = [strongest_chain]
        valid_pairs = []
        valid_indexes = []
        for peer, ip, headers, idx in header_valid:
            get_blocks(idx, peer)
            chain = listen_for_blocks(peer, index=headers[0]["index"]) or []
            if not check_headers_and_blocks(chain, headers):
                used_addresses.add(ip)
                peer.close()
                continue
            peer_chains.append(chain)
            valid_pairs.append((peer, ip))
            valid_indexes.append(idx)

        # 5) Wenn immer noch nur die eigene Chain da ist, neu versuchen
                # 6) Erfolgreich: stärkste Chain ermitteln und anwenden / Header senden
        for chain in peer_chains:
            for block in chain:
                adding_new_block(block=block, node=node, block_file_path=chain_path)
        node.update_strongest_chain()
        new_strongest_chain = node.get_strongest_chain()
        if new_strongest_chain == strongest_chain:
            block_packages = get_full_block_packages(node=node, block_file_path=chain_path,idx=min(valid_indexes),package_size=block_package_size)
            for i in block_packages:
                for block in i: 
                    for peer in peers:
                        send_block(block=block,peer=peer)

        break  # wir haben jetzt >1 Chain
    deductions = [ip for ip in used_addresses]
    # 8) Beende Sync-Modus, speichere alle Peers, die verbunden waren
    saving_node.update_peers(active_peers)
    saving_node.update_strongest_chain()
    saving_node.deduct_peers(deductions)


    
mining_lock = Lock()
threads_stated = False
saving_node.update_known_addresses(adresses)
mining = True

if __name__ == "__main__":
    while True:
        if not syncing_active:
            sync( node=saving_node, standard_port=standart_port, peers_number= max_connection_number, chain_path=chain_path
                
            )
            syncing_active = False
        if not threads_stated:
            for peer in saving_node.get_peers():
                threading.Thread(target=start_peer_thread, args=(peer,saving_node),daemon=True).start()
            threading.Thread(target=start_server, args=(standart_port, saving_node), daemon=True).start()
            threads_stated = True
        
        action = input("Enter action type:")
        if action == "mining":
            print("Mining started")
            threading.Thread(target=mine, args=(saving_node, chain_path, public_key), daemon=True).start()
        if action == "transaction":
            recipient = input("Enter reciepient adress:")
            amount = float(input("Enter Amount: "))
            fee = float(input("Enter fee:"))
            peers = saving_node.get_peers()
            nonce = saving_node.get_nonce()
            if nonce == None:
                nonce = 0
            signature = sign_transaction(private_key_pem=privat_key, recipient=recipient, amount=amount, sender= pem_str, fee=fee, nonce= nonce)
            transaction = {
                "sender_public_key": pem_str,
                "recipient_public_key": recipient,
                "amount": amount,
                "fee": fee,
                "signature": signature,
                "nonce": nonce
            }
            saving_node.add_to_trans(transaction=transaction)
            print(saving_node.balances)
            print(saving_node.all_nonces)
            for peer in peers:
                send_transaction(tx=transaction, peer=peer)
            saving_node.sync_own_nonce()
        time.sleep(2)
        
        if action == "EXIT":
            break
        time.sleep(2)
peers = saving_node.get_known_addresses()
save_peers(peers=peers, path=peer_path)