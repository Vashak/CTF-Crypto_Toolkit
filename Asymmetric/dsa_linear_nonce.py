"""
=========================================================
🎯 Objective: DSA Private Key Recovery via Related Nonces
💀 Vulnerability: Linear Nonce Increment (k2 = k1 + 1337)
🛠️ Method: 
   1. Requests two signatures from the server.
   2. Exploits the linear relationship between the nonces to build a system of equations modulo q.
   3. Isolates and calculates the server's private key (x).
   4. Clones the signing function locally using a custom nonce (k = 420) to forge a valid signature and bypass command filters.
=========================================================
"""
from pwn import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long, inverse

# --- 1. PARAMETRI STATICI (Dal sorgente) ---
q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4b
p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5

def main():
    print("[*] Avvio cantiere DSA...")
    r = remote('lineardsa.challs.cyberchallenge.it', 9067)

    # --- 2. ESTRAZIONE VARIABILE PUBBLICA (g) ---
    r.recvuntil(b"> ")
    r.sendline(b"3")
    # Il server stampa "(g, y)". Pigliamo tutto, togliamo le parentesi e splittiamo.
    parametri = r.recvline().strip().decode().replace('(', '').replace(')', '').split(', ')
    g = int(parametri[0])
    # y = int(parametri[1])  # (Opzionale: non ci serve per forgiare, ma potevamo salvarlo)
    print("[+] Generatore (g) estratto.")

    # --- 3. CATTURA DELLE DUE FIRME ---
    msg1 = b"A"
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b": ")
    r.sendline(msg1)
    sig1_hex = r.recvline().strip().decode()
    r1 = int(sig1_hex[:40], 16)
    s1 = int(sig1_hex[40:], 16)
    print("[+] Firma 1 per 'A' ottenuta.")

    msg2 = b"B"
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b": ")
    r.sendline(msg2)
    sig2_hex = r.recvline().strip().decode()
    r2 = int(sig2_hex[:40], 16)
    s2 = int(sig2_hex[40:], 16)
    print("[+] Firma 2 per 'B' ottenuta.")

    # --- 4. CALCOLO DEGLI HASH ---
    H1 = bytes_to_long(sha1(msg1).digest())
    H2 = bytes_to_long(sha1(msg2).digest())

    # --- 5. IL FURTO DELLA CHIAVE PRIVATA (Magia Algebrica) ---
    print("[*] Calcolo della chiave privata (x) in corso...")
    inv_s1 = inverse(s1, q)
    inv_s2 = inverse(s2, q)

    numeratore = (-1337 - (inv_s1 * H1) + (inv_s2 * H2)) % q
    denominatore = (r1 * inv_s1 - r2 * inv_s2) % q

    x = (numeratore * inverse(denominatore, q)) % q
    print(f"[+] CHIAVE PRIVATA (x) TROVATA: {hex(x)}")

    # --- 6. FUNZIONE DI FIRMA CLONATA ---
    def sign_copia(m):
        k = 420  # Il nostro nonce "swag"
        H = bytes_to_long(sha1(m).digest())
        r_falso = pow(g, k, p) % q
        s_falso = (inverse(k, q) * (H + x * r_falso)) % q
        return hex(r_falso)[2:].rjust(40,'0') + hex(s_falso)[2:].rjust(40,'0')

    # --- 7. CREAZIONE FIRMA MAGICA E INCASSO ---
    target_msg = b"gimme the flag"
    firma_magica = sign_copia(target_msg)
    print(f"[*] Firma forgiata creata con successo.")

    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b": ")
    r.sendline(target_msg)
    r.recvuntil(b": ")
    r.sendline(firma_magica.encode())

    # --- 8. LA VITTORIA ---
    print("\n[+] RISPOSTA DEL SERVER:")
    print(r.recvall(timeout=2).decode())

if __name__ == "__main__":
    main()
"""
#!/usr/bin/env python3

import signal
import os
from hashlib import sha1
import random
import time
from Crypto.Util.number import bytes_to_long, inverse
import sys

TIMEOUT = 300

assert("FLAG" in os.environ)
FLAG = os.environ["FLAG"]
assert(FLAG.startswith("CCIT{"))
assert(FLAG.endswith("}"))

class DSA:
    def __init__(self):
        self.q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4b
        self.p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5
        self.h = random.randint(2,self.p-2)
        self.g = pow(self.h, (self.p-1)//self.q, self.p)
        self.x = random.randint(1, self.p-1)
        print(self.x%self.q, file=sys.stderr)
        self.y = pow(self.g, self.x, self.p)
        self.k = random.randint(1, self.q-1)

    def sign(self, m):
        self.k += 1337
        print(self.k%self.q, file=sys.stderr)
        H = bytes_to_long(sha1(m).digest())
        r = pow(self.g, self.k, self.p) % self.q
        s = (inverse(self.k, self.q)*(H + self.x*r)) % self.q
        assert(s != 0)
        return hex(r)[2:].rjust(40,'0') + hex(s)[2:].rjust(40,'0')

    def verify(self, m, sig):
        r, s = int(sig[:40],16), int(sig[40:],16)
        a = pow(self.g, (bytes_to_long(sha1(m).digest())*inverse(s,self.q)) % self.q, self.p)
        b = pow(self.y, (r*inverse(s, self.q)) % self.q, self.p)
        return (a*b % self.p) % self.q == r


def handle():
    signer = DSA()

    while True:
        print("What do you want to do?")
        print("1. Sign command")
        print("2. Execute command")
        print("3. Print public parameters")
        print("0. Exit")

        choice = int(input("> "))
        if choice == 1:
            cmd = input("Input a command: ").strip().encode()
            if b"flag" in cmd:
                print("I can't sign this, sorry.")
            else:
                print(signer.sign(cmd))
        elif choice == 2:
            cmd = input("Input a command: ").strip().encode()
            sig = input("Input the signature: ").strip()
            if signer.verify(cmd, sig):
                if cmd == b"gimme the flag":
                    print(FLAG)
                else:
                    print("That's a nice command, good job!")
            else:
                print("Invalid signature")
        elif choice == 3:
            print((signer.g, signer.y))
        else:
            return


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
"""

