"""
-------------------------------------------------------------------------------
🎯 Objective: SHA1 Length Extension & Logic Truncation Bypass
💀 Vulnerability: MAC computed on Base64 string + Insecure split() parsing
🛠️ Method:
   1. Obtains a valid SHA1 MAC (Testimone) for a Base64 encoded payload.
   2. Uses hlextend to forge a new hash by calculating the exact SHA1 padding.
   3. Appends the malicious tail: '&id=0&name=flag&author=admin'.
   4. Re-encodes the forged payload in Base64 before sending it to the server.
   5. Exploits `data.split(b"&")[1:]` to truncate the original payload and padding,
      forcing the server to parse only the injected cleartext parameters.
-------------------------------------------------------------------------------
"""
from pwn import *
import base64
import hlextend

def main():
    context.log_level = 'error'
    print("[+] Accensione macchinari... ")
    r = remote('extendme.challs.cyberchallenge.it', 9069)

    # --- FASE 1: OTTENIAMO IL TESTIMONE ---
    # Creiamo una nota con i dati richiesti dai controlli logici
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"flag")
    r.sendlineafter(b"> ", b"admin")
    r.sendlineafter(b"> ", b"c")

    r.recvuntil(b"identifier ")
    # Questo è il base64 (es. JmlkPTEmbmFtZT1mbGFnJmF1dGhvcj1hZG1pbg==)
    ident_b64 = r.recvuntil(b" ")[:-1]  
    
    r.recvuntil(b"checksum ")
    check_orig = r.recvuntil(b".")[:-1].decode()

    print(f"[-] Stringa Base64 (Dati noti per lo SHA1): {ident_b64.decode()}")
    print(f"[-] Testimone: {check_orig}")

    # --- FASE 2: LA MAGIA DELLA LENGTH EXTENSION ---
    # La coda ripulisce tutto e imposta id=0.
    coda_malvagia = b"&id=0&name=flag&author=admin"
    
    sha = hlextend.new('sha1')
    lunghezza_salt = 16 # Sappiamo che è 16 per l'assert del server!
    
    print("\n[+] Costruzione del Payload...")
    # ATTENZIONE QUI: Estendiamo ident_b64, NON il testo in chiaro!
    payload = sha.extend(coda_malvagia, ident_b64, lunghezza_salt, check_orig)
    hash_falsificato = sha.hexdigest()

    # --- FASE 3: CONSEGNA ALLA DOGANA ---
    print("[+] Invio del carico alla dogana...")
    r.sendlineafter(b"> ", b"2")
    
    # Il payload è già la stringa esatta che vogliamo far hashare alla Dogana.
    # Siccome la Dogana fa una b64decode, noi dobbiamo impacchettarlo in Base64!
    r.sendlineafter(b"> ", base64.b64encode(payload))
    r.sendlineafter(b"> ", hash_falsificato.encode())

    # Raccogliamo la Flag!
    print("\n--- RISULTATO DEL SERVER ---")
    risultato = r.recvall(timeout=2).decode()
    
    # Puliamo un po' l'output
    if "What do you want to do?" in risultato:
        print(risultato.split("What do you want to do?")[0].strip())
    else:
        print(risultato.strip())

if __name__ == "__main__":
    main()

"""
#!/usr/bin/env python3

import signal
import os
import hashlib
from base64 import b64encode, b64decode

TIMEOUT = 300

assert("FLAG" in os.environ)
FLAG = os.environ["FLAG"]
assert(FLAG.startswith("CCIT{"))
assert(FLAG.endswith("}"))

assert("SALT" in os.environ)
SALT = os.environ["SALT"]
assert(len(SALT) == 16)

notes = {0: ("flag", "admin", FLAG)}

counter = 1


def add_note():
    global counter

    note = {}
    print("Name of the note")
    name = input("> ").strip()
    print("Author of the note")
    author = input("> ").strip()

    if "&" in name or "=" in name or "&" in author or "=" in author:
        print("Nice try")
        return

    note["id"] = str(counter)
    note["name"] = name
    note["author"] = author

    super_secret_identifier = ""
    for k in note:
        super_secret_identifier += "&"+k+"="+note[k]
    print("Content of the note")
    content = input("> ").strip()

    super_secret_identifier = b64encode(super_secret_identifier.encode())
    check = hashlib.sha1(SALT.encode() + super_secret_identifier).hexdigest()
    notes[counter] = (name, author, content)
    counter += 1
    print(
        f"Successfully added note {name} with identifier {super_secret_identifier.decode()} and checksum {check}.")


def retrieve_note():
    print("Give me the note identifier")
    identifier = b64decode(input("> ").strip().encode())
    print("Give me the note checksum")
    check = input("> ").strip().encode()
    if hashlib.sha1(SALT.encode() + identifier).hexdigest().encode() != check:
        print("Pls stop hacking")
        return
    note = {}
    try:
        data = identifier.split(b"&")[1:]
        for el in data:
            key, value = el.split(b"=")
            note[key] = value
        retrieved_note = notes[int(note[b"id"])]
        if note[b"author"] in retrieved_note[1].encode() and note[b"name"] in retrieved_note[0].encode():
            print(retrieved_note)
    except:
        print("Something wrong")


def handle():
    while True:
        print("What do you want to do?")
        print("1. Add note")
        print("2. Retrieve note")
        print("0. Exit")
        choice = int(input("> ").strip())
        if choice == 1:
            add_note()
        elif choice == 2:
            retrieve_note()
        else:
            exit()


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
"""
