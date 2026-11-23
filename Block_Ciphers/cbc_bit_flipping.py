"""
=========================================================
🎯 Objective: CBC Bit-Flipping Authentication Bypass
💀 Vulnerability: Unauthenticated IV / CBC Malleability
🛠️ Method: 
   1. Registers a dummy account ("bdmin") to receive a valid login token (IV + Ciphertext).
   2. Exploits the CBC decryption property: Plaintext = Decrypt(Ciphertext) ⊕ IV.
   3. Modifies a specific byte in the IV using XOR arithmetic (IV[12] ⊕ 'b' ⊕ 'a') to alter the decrypted plaintext from "bdmin" to "admin".
   4. Sends the forged token to impersonate the administrator and execute privileged commands.
=========================================================
"""
from pwn import *
import ast

host = "predictable.challs.cyberchallenge.it"
port = 9034
r = remote(host, port)

print("[+] Connessione stabilita. Inizio l'attacco...")

# 1. OPZIONE 4: Rubiamo l'IV dell'admin (Leggiamo il database)
r.recvuntil(b"> ")
r.sendline(b"4")
db_string = r.recvline().decode().strip()
# Trasformiamo la stringa del server in un vero dizionario Python
db = ast.literal_eval(db_string) 
iv_admin = db['admin']
print(f"[+] IV Admin recuperato: {iv_admin}")

# 2. OPZIONE 1: Registrazione dell'esca ("bdmin")
r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b"Insert your username: ")
r.sendline(b"bdmin")
r.recvuntil(b"Your login token: ")
login_token = r.recvline().decode().strip()
print(f"[+] Token 'bdmin' ottenuto: {login_token}")

# 3. LA MAGIA: Bit-Flipping (XOR)
# Dividiamo IV e Ciphertext
iv_originale = bytearray.fromhex(login_token[:32])
ciphertext = login_token[32:]

# Malleabilità CBC: Cambiamo la 'b' in 'a' all'indice 12
iv_originale[12] = iv_originale[12] ^ ord('b') ^ ord('a')

# Ricreiamo il token falso
token_falso = iv_originale.hex() + ciphertext
print(f"[+] Token falsificato creato: {token_falso}")

# 4. OPZIONE 2: Usiamo il token falso per fargli credere che siamo admin
r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b"Please give me your login token ")
r.sendline(token_falso.encode())

# Il server ci dà il benvenuto come admin!
print(r.recvline().decode().strip()) 

# Ora ci chiede il comando. Ricorda: lo vuole in esadecimale!
r.recvuntil(b"What command do you want to execute? ")
comando_hex = b"get_flag".hex().encode()
r.sendline(comando_hex)

r.recvuntil(b"Your command token: ")
command_token = r.recvline().decode().strip()
print(f"[+] Token del comando generato (con IV dell'admin!): {command_token}")

# 5. OPZIONE 3: Il colpo di grazia
r.recvuntil(b"> ")
r.sendline(b"3")
r.recvuntil(b"What do you want to do? ")
r.sendline(command_token.encode())

# 6. INCASSIAMO LA FLAG
risultato = r.recvline().decode().strip()
print(f"{risultato}")

r.close()
"""
#!/usr/bin/env python3

import signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

TIMEOUT = 300

assert("FLAG" in os.environ)
flag = os.environ["FLAG"]
assert(flag.startswith("CCIT{"))
assert(flag.endswith("}"))

key = os.urandom(16)
db = {'admin': os.urandom(16).hex()}


def handle():
    while True:
        print("1. Register")
        print("2. Generate command tokens")
        print("3. Execute commands with token")
        print("4. See database")
        print("0. Exit")
        choice = int(input("> "))
        if choice == 1:
            name = input("Insert your username: ")
            if ":" in name:
                continue
            if name not in db:
                cookie = f"login_token:{name}".encode()
                iv = os.urandom(16)
                db[name] = iv.hex()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(cookie, 16))
                print(f"Your login token: {iv.hex()+encrypted.hex()}")
            else:
                print("Username already registered")
        elif choice == 2:
            token = input("Please give me your login token ")
            try:
                cookie = bytes.fromhex(token[32:])
                iv = bytes.fromhex(token[:32])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(cookie), 16).decode()
                values = pt.split(":")
                if values[0] == "login_token":
                    print("Welcome back {}".format(values[1]))
                    command = bytes.fromhex(input(
                        "What command do you want to execute? "))
                    iv = bytes.fromhex(db[values[1]])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    encrypted = cipher.encrypt(pad(command, 16))
                    print(f"Your command token: {iv.hex()+encrypted.hex()}")
                else:
                    print("It seems that this is not a login token.")
            except:
                print("Something went wrong")
        elif choice == 3:
            token = input("What do you want to do? ")
            try:
                cmd = bytes.fromhex(token[32:])
                iv = bytes.fromhex(token[:32])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(cmd), 16)
                if pt == b"get_flag":
                    if iv == bytes.fromhex(db['admin']):
                        print(f"Here is your flag: {flag}")
                    else:
                        print("Only admin can see the flag.")
                else:
                    print("Nice command! But it seems useless...")
            except:
                print("Something went wrong")
        elif choice == 4:
            print(db)
        else:
            break


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
"""
