"""
=========================================================
🎯 Objective: ChaCha20 Keystream Leak
💀 Vulnerability: Known Plaintext Attack (KPA) via Null-byte Injection
🛠️ Method: 
   1. Leverage the XOR property: Plaintext ⊕ Keystream = Ciphertext.
   2. By sending a null-byte payload (b"00"*16), the output becomes the raw Keystream.
   3. Use the leaked keystream to XOR and decrypt the hidden flag.
=========================================================
"""
from pwn import *
def xor_bytes(a, b):
    return bytes([a[i%len(a)]^b[i%len(b)]for i in range(max(len(a), len(b)))])
#molto intuitivo a dire il vero
r=remote('danceable.challs.cyberchallenge.it', 9036)
r.recvuntil(b"0. Exit")
r.sendline(b"1")
r.recvuntil(b"?")
r.sendline(b"00" * 16)
outp=r.recvline().strip().decode() 
outp=bytes.fromhex(outp)
flag=xor_bytes(outp[:16], outp[16:])
print(flag.decode())

"""
#!/usr/bin/env python3

from Crypto.Cipher import ChaCha20
import os
import signal
from Crypto.Util.Padding import pad, unpad

TIMEOUT = 300

assert("FLAG" in os.environ)
flag = os.environ["FLAG"]
assert(flag.startswith("CCIT{"))
assert(flag.endswith("}"))

nonce = os.urandom(8)
key = os.urandom(32)


def encrypt(text):
    text = bytes.fromhex(text)
    to_encrypt = text + flag.encode()
    assert len(to_encrypt) < 256, "The message is too long!"
    padded = pad(to_encrypt, 16)
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    ct = b""
    for block in blocks:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ct += cipher.encrypt(block)
    return ct.hex()


def handle():
    while True:
        print("1. Encrypt")
        print("0. Exit")
        choice = int(input("> "))
        if choice == 1:
            text = input("What do you want to encrypt (in hex)? ").strip()
            print(encrypt(text))
        else:
            break


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()

"""
