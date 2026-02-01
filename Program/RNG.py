import secrets
import hashlib

def support_shrink_hash_expand(k: int, nbytes: int) -> bytes:
    r = secrets.randbits(k)
    r_bytes = r.to_bytes((k + 7) // 8, "big")
    return hashlib.sha256(r_bytes).digest()[:nbytes]

def bit_bias(eps: float, nbytes: int) -> bytes:
    out = bytearray((nbytes * 8 + 7) // 8)
    for i in range(nbytes * 8):
        if secrets.randbelow(10**6) < int((0.5 + eps) * 10**6):
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)

def markov_correlation(delta: float, nbytes: int) -> bytes:
    stay = 0.5 + delta
    out = bytearray((nbytes * 8 + 7) // 8)
    prev = secrets.randbelow(2)
    for i in range(nbytes * 8):
        if i > 0 and secrets.randbelow(10**6) >= int(stay * 10**6):
            prev ^= 1
        if prev:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)

n = 10
nbytes = 16
for i in range(n):
    su = support_shrink_hash_expand(64,nbytes)
    bias = bit_bias(0.5,nbytes)
    print(format(int.from_bytes(su,"big"),"0128b"))
    print(format(int.from_bytes(bias,"big"),"0128b"))

