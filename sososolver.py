import base64
from Crypto.Cipher import Salsa20

# 1. The Encrypted String from password.txt [cite: 1]
enc_b64 = "l/91qeiC30SlA/2t9i/v59T/3QbU"

# 2. Extract Key and Nonce from the binary dump
# The Key is 32 bytes long, located at address 100003000 (_KEY)
# Data extracted from lines 139-154 in the provided file 
key_bytes = bytes([
    0xd3, 0xfc, 0x98, 0xf2, 0x46, 0xd5, 0x8c, 0x00,
    0x22, 0x85, 0x90, 0x4d, 0x61, 0x20, 0xd2, 0x05,
    0xcd, 0x7e, 0xb0, 0xb5, 0x42, 0x45, 0x76, 0x4b,
    0xe4, 0x94, 0x71, 0x2a, 0x7a, 0xec, 0x54, 0x9e
])

# The Nonce is 8 bytes long, located at address 100003020 (_NONCE)
# Data extracted from lines 158-165 in the provided file 
nonce_bytes = bytes([
    0x1c, 0x0a, 0xea, 0x05, 0xc0, 0xae, 0xae, 0x60
])

def solve():
    # Step A: Decode the Base64 string back to raw encrypted bytes
    ciphertext = base64.b64decode(enc_b64)

    # Step B: Initialize Salsa20 cipher
    # The decompiled code uses standard Salsa20 constants ("expand 32-byte k")
    cipher = Salsa20.new(key=key_bytes, nonce=nonce_bytes)

    # Step C: Decrypt
    # Since Salsa20 is a stream cipher (XOR based), encrypt and decrypt are the same operation.
    plaintext = cipher.decrypt(ciphertext)

    print(f"Flag: {plaintext.decode('utf-8')}")

if __name__ == "__main__":
    solve()
