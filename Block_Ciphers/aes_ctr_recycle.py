"""
=========================================================
🎯 Objective: AES-CTR Keystream Reuse & Counter Sync
💀 Vulnerability: Nonce Length Manipulation
🛠️ Method: 
   1. Set a long nonce (15 bytes) to encrypt the flag at a specific counter state.
   2. Shorten the nonce (14 bytes) to allow more counter space, preventing server crashes.
   3. Desync the counter by 252 iterations to align with the flag's encryption block.
   4. Perform a Known Plaintext Attack (KPA) to leak the keystream and decrypt the flag.
=========================================================
"""
from pwn import *

r = remote('recycle.challs.cyberchallenge.it', 38213)

def xor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])

log.info("--- ATTACCO 'RECYCLE' (NO CRASH) ---")

# 1. NONCE 1 (15 byte: 14 di zeri + 01)
# In hex: 28 zeri e un "01" finale
r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"> ", b"00" * 14 + b"01")

r.sendlineafter(b"> ", b"2")
c_flag = bytes.fromhex(r.recvline().decode().strip())
log.success(f"Flag catturata! (Lunga {len(c_flag)} byte)")

# 3. CAMBIO NONCE (14 byte di zeri) -> IL TRUCCO SALVA-VITA
# Questo dà al contatore 2 byte di spazio (max 65535), evitando il crash a 256!
r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"> ", b"00" * 14)
log.info("Nonce accorciato a 14 byte per prevenire il crash.")

spari = 252
log.info(f"Lancio {spari} spari per l'allineamento...")
r.send(b"1\n" * spari)

# Puliamo il buffer con precisione
for i in range(spari):
    r.recvuntil(b"> ") # Consuma il menu
    r.recvline()       # Consuma P e C
    if i % 50 == 0:
        print(f"Avanzamento... {i}/{spari}")

log.success("Counter a 256. Allineamento perfetto coi blocchi della flag!")

# La flag è lunga 4 blocchi (52 byte), quindi ci servono i prossimi 4 keystream
all_keystreams = b""
log.info("Estrazione dei 4 veli crittografici...")

for i in range(4):
    r.sendlineafter(b"> ", b"1")
    line = r.recvline().decode().strip().split()
    p_rand = bytes.fromhex(line[0])
    c_rand = bytes.fromhex(line[1])
    all_keystreams += xor(p_rand, c_rand)


final_flag = xor(c_flag, all_keystreams)
print(f"FLAG: {final_flag.decode(errors='ignore')}")

r.close()
"""

from Crypto.Cipher import AES
import os
import math

flag = os.getenv("FLAG", "CCIT{redacted}")

flag = flag.encode()
key = os.urandom(16)
nonce = os.urandom(8)

cipher = AES.new(key, AES.MODE_CTR, nonce = nonce, initial_value = 0)
counter_value = 0

while True:
    print("What do you want to do?")
    print("1. Encrypt a block")
    print("2. Encrypt the flag")
    print("3. Change nonce")
    try:
        choice = int(input("> "))

        if choice == 3:
            nonce = bytes.fromhex(input("> ").strip())
        elif choice == 1:
            block = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CTR, nonce = nonce, initial_value = counter_value)
            enc = cipher.encrypt(block)
            print(block.hex(), enc.hex())
            counter_value += 1
        elif choice == 2:
            cipher = AES.new(key, AES.MODE_CTR, nonce = nonce, initial_value = counter_value)
            enc = cipher.encrypt(flag)
            print(enc.hex())
            counter_value += math.ceil(len(flag)/16)
    except:
        print("Something went wrong")
        exit()
"""
