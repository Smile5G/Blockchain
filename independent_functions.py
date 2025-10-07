import json
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
def load_chain(path):
    """
    Lädt die Blockchain-Datei und gibt sie als Liste von Blöcken zurück.
    """
    chain = []
    with open(path, "r", encoding="utf-8") as f:
        for block in ijson.items(f, "item"):
            chain.append({
                "hash": block.get("hash"),
                "previous_hash": block.get("previous_hash"),
                "index": block.get("index"),
                "timestamp": block.get("timestemp")
            })
    return chain
# Extracts all possible chains from the blockchain content, considering forks
def extract_all_chains(chain_content):
    # hash → block
    hash_map = {block["hash"]: block for block in chain_content}

    # previous_hash → [children]
    children_map = defaultdict(list)
    for block in chain_content:
        children_map[block["previous_hash"]].append(block)

    # alle Startblöcke (Genesis o.ä.)
    start_blocks = [b for b in chain_content if b["previous_hash"] == "0"]

    def build_chains(current_block):
        if current_block["hash"] not in children_map:
            return [[current_block]]
        chains = []
        for child in children_map[current_block["hash"]]:
            for subchain in build_chains(child):
                chains.append([current_block] + subchain)
        return chains

    all_chains = []
    for start in start_blocks:
        all_chains.extend(build_chains(start))
    
    return all_chains


# Estimates the target difficulty value for a given block index in the chain
def estimate_target_values(chain, check_index, star_value=1.286e70, span=2016, expected_time_difference=180 ):
    check_index = min(check_index, len(chain) - 1)

    if check_index < span:
        return star_value

    # Berechne Startindex des Intervalls
    end_index = (check_index - 1) // span * span
    start_index = end_index - span

    # Sicherstellen, dass beide Indizes innerhalb der Kette liegen
    if start_index <0:
        return star_value

    older_timestamp = chain[start_index]["timestamp"]
    newer_timestamp = chain[end_index]["timestamp"]

    # Zeitdifferenz in Sekunden
    time_difference = newer_timestamp - older_timestamp
    factor = time_difference/ expected_time_difference
    return star_value/factor

# Returns the strongest chain based on cumulative difficulty estimates
def get_strongest_chain(chains):
    strengths= []
    for ix, i in enumerate(chains): 
        strength = sum(1 / estimate_target_values(i, x) for x in range(len(i)))
        strengths.append(strength)
    return chains[strengths.index(max(strengths))]
