"""
🎯 Objective: Diffie-Hellman Shared Secret Recovery via Cryptographic Oracle

💀 Vulnerability: Key Reuse & Lack of input validation on public parameters (g, pub)

🛠️ Method:
1. Intercepts the original Diffie-Hellman exchange parameters: p, pubA, pubB, and the encrypted flag.
2. Initiates a new session with Bob, who reuses his original private key (privB).
3. Injects the original prime 'p', but poisons the parameters by sending g = pubA and pub = pubA.
4. Forces Bob to compute pubB = (pubA)^privB mod p, which mathematically equals the original shared secret.
5. Bob unwittingly prints the computed shared secret back to the terminal.
6. Hashes the leaked secret with SHA256 to derive the AES-ECB key and decrypts the original intercepted flag.
-------------------------------------------------------------------------------
"""
from pwn import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
r=remote('carol.challs.cyberchallenge.it', 9045)
r.recvuntil(b"p: ")
p=int(r.recvline().strip())

r.recvuntil(b"pubA: ")
pubA=int(r.recvline().strip())

r.recvuntil(b"pubB: ")
pubB=int(r.recvline().strip())

r.recvuntil(b"flag: ")
ctflag=r.recvline().strip().decode()

r.recvuntil(b"prime: ")
r.sendline(str(p).encode())

r.recvuntil(b"ator: ")
r.sendline(str(pubA).encode())

r.recvuntil(b": ")
r.sendline(str(pubA).encode())

r.recvuntil(b"essage: ")
r.sendline(b"CCIT")

r.recvuntil(b": ")
output=int(r.recvline().strip())

key = hashlib.sha256(long_to_bytes(output)).digest()[:16]
cipher=AES.new(key, AES.MODE_ECB)
flag=unpad(cipher.decrypt(bytes.fromhex(ctflag)), 16)
print(flag) 


"""
#!/usr/bin/env python3

import signal
import os
import random
import hashlib
from Crypto.Util.number import getStrongPrime, long_to_bytes, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

TIMEOUT = 300

assert("FLAG" in os.environ)
FLAG = os.environ["FLAG"]
assert(FLAG.startswith("CCIT{"))
assert(FLAG.endswith("}"))

assert("NBITS" in os.environ)
NBITS = int(os.environ["NBITS"])


def handle():
    p = getStrongPrime(NBITS)
    g = 2

    def gen_key():
        s = random.randint(0, 2**NBITS)
        return s, pow(g, s, p)

    privA, pubA = gen_key()
    privB, pubB = gen_key()

    shared_secret = pow(pubA, privB, p)
    key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(FLAG.encode(), 16)).hex()

    print("See how Alice successfully exchanged a message with Bob:")
    print(f"p: {p}")
    print(f"pubA: {pubA}")
    print(f"pubB: {pubB}")
    print(f"Encrypted flag: {ct}")
    print()
    print("Now you can exchange messages with Bob too!")
    p = int(input("Enter your prime: "))
    g = int(input("Enter the generator: "))
    pub = int(input("Enter your public value: "))
    msg = input("Enter your message: ").encode()

    assert isPrime(p), "Please provide a prime p"
    assert p.bit_length() >= NBITS, "Please use a bigger prime"

    pubB = pow(g, privB, p)
    shared_secret = pow(pub, privB, p)
    key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(msg, 16)).hex()
    print(f"pubB: {pubB}")
    print(f"Here's the encrypted message: {ct}")


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
"""
