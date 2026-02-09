import secrets
from Crypto.Cipher import AES

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def ctr_keystream(key: bytes, IV: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    ctr = (0).to_bytes(8,"big")
    output = aes.encrypt(IV + ctr)

    return output

# massage can be only 16 bytes. This is a one block algorithms.
def aes_encrypt(
        massage: bytes, 
        key: bytes, 
        IV: bytes,
        ):
    key_stream = ctr_keystream(key,IV)
    ciphertext = xor_bytes(key_stream,massage)

    return ciphertext
