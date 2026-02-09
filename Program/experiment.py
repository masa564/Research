import secrets
import os
import math
import matplotlib.pyplot as plt
import csv
from Crypto.Cipher import AES
from encrypt import ctr_keystream, xor_bytes, aes_encrypt
from RNG import markov_correlation, bit_bias, support_shrink_hash_expand
from typing import Callable, Dict
from collections import Counter


def IND_game (nonces_oracle, nonce_challenge, q: int) -> int:
    """
    nonces_oracle   : list[bytes]  length >= q
    nonce_challenge : bytes
    return 1 if adversary wins, else 0
    """

    key = secrets.token_bytes(32)

    seen = {}
    M0 = bytes([0x00]) * 64
    M1 = bytes([0xFF]) * 64

    # --- Oracle phase ---
    for i in range(q):
        n = nonces_oracle[i]
        c = aes_encrypt(key, M0, n)
        if n not in seen:
            seen[n] = c   # keystream for this nonce

    # --- Challenge ---
    b = secrets.randbelow(2)
    Mb = M0 if b == 0 else M1
    c_star = aes_encrypt(key, Mb, nonce_challenge)

    # --- Adversary ---
    if nonce_challenge in seen:
        ks = seen[nonce_challenge]
        rec = xor_bytes(c_star, ks)
        if rec == M0:
            b_hat = 0
        elif rec == M1:
            b_hat = 1
        else:
            b_hat = secrets.randbelow(2)
    else:
        b_hat = secrets.randbelow(2)

    return 1 if b_hat == b else 0


# ========= Advantage estimation =========

def estimate_advantage(nonce_sequences, q: int) -> float:
    """
    nonce_sequences: list of (nonces_oracle, nonce_challenge)
    """
    wins = 0
    for nonces_oracle, nonce_challenge in nonce_sequences:
        wins += IND_game(nonces_oracle, nonce_challenge, q)

    p = wins / len(nonce_sequences)
    return abs(p - 0.5)


def ctr_keystream_break(
    trials: int,
    n: int,
    k: int,             #value of entropy in IV
    nbytes: int         #value of IV length as bytes
) -> Dict[str, float]:
    results = []
    for _ in range(trials):
        key = secrets.token_bytes(16)
        ks_db = {}
        

        for _ in range(n):
            IV = support_shrink_hash_expand(k,nbytes)
            ks = ctr_keystream(key, IV)

            if IV not in ks_db:
                ks_db[IV] = ks
        
        ks_sample = list(ks_db.values())


        # collision rate
        total = n
        unique = len(ks_sample)
        collision_rate = 1-(unique/total)


        # bit bias
        bit_count = [0] * 128
        
        for ks in ks_sample:
            for i, byte in enumerate(ks):
                for b in range(8):
                    if byte & (1 << b):
                        bit_count[i*8 + b] += 1
        
        bias = []
        for count in bit_count:
            p = count / n
            bias.append(abs(p - 0.5))
        
        avg_bias = sum(bias) / len(bias)


        # Hamming distance
        distances =[]
        
        for i in range(unique):
            for j in range(i+1, unique):
                d = sum(
                    bin(x^y).count("1")
                    for x, y in zip(ks_sample[i], ks_sample[j])
                )
                distances.append(d)

        if distances:
            avg_hd = sum(distances) / len(distances)
        else:
            avg_hd = 0


        # Entropy
        counter = Counter(ks_sample)
        
        entoropy = 0.0
        for count in counter.values():
            p = count / unique
            entoropy -= p*math.log2(p)

        results.append({
            "Collision_rate": collision_rate,
            "Avg_bias": avg_bias,
            "Avg_Hamming_distance": avg_hd,
            "Entropy": entoropy
        })

    return {
        "Collision_rate": sum(r["Collision_rate"] for r in results) /trials,
        "Avg_bias": sum(r["Avg_bias"] for r in results) /trials,
        "Avg_Hamming_distance": sum(r["Avg_Hamming_distance"] for r in results) /trials,
        "Entropy": sum(r["Entropy"] for r in results) /trials,
        }
        


trials = 1
n = 50
nbytes = 8 # bytes
ks = list(range(1,65,2))
collision = []
avg_bias = []
avg_hd = []
entropy =[]

for k in  ks: # k is bit values
    r = ctr_keystream_break(trials, n, k, nbytes)
    collision.append(r["Collision_rate"])
    avg_bias.append(r["Avg_bias"])
    avg_hd.append(r["Avg_Hamming_distance"])
    entropy.append(r["Entropy"])

plt.figure()
plt.plot(ks, collision, marker="o")
plt.xlabel("k (bits)")
plt.ylabel("Collision rate")
plt.title("Collision rate vs k")
plt.grid(True)
plt.show()

plt.figure()
plt.plot(ks, avg_bias, marker="o")
plt.xlabel("k (bits)")
plt.ylabel("Average bit bias")
plt.title("Average bit bias vs k")
plt.grid(True)
plt.show()

plt.figure()
plt.plot(ks, avg_hd, marker="o")
plt.xlabel("k (bits)")
plt.ylabel("Average Hamming distance")
plt.title("Average Hamming distance vs k")
plt.grid(True)
plt.show()

plt.figure()
plt.plot(ks, entropy, marker="o")
plt.xlabel("k (bits)")
plt.ylabel("Entropy (bits)")
plt.title("Entropy vs k")
plt.grid(True)
plt.show()

with open ("keystream_evaluation.csv", "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "k_bits",
        "collision_rate",
        "avg_bias",
        "avg_hamming_distance",
        "entropy"
    ])

    for i in range(len(ks)):
        writer.writerow([
            ks[i],
            collision[i],
            avg_bias[i],
            avg_hd[i],
            entropy[i]
        ]) 