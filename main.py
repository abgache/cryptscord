import os
import time
import threading
import requests
import subprocess as sub
from scripts.rsa_utils import *
from scripts.crypto import AES
from scripts.time_log import time_log_module as tlm
from scripts.logger import logger

version="2.0"

def send(msg):
        r = requests.post(BASE_URL, headers=HEADERS, json={"content": msg})
        if r.status_code == 200:
            my_message_ids.append(r.json()["id"])

    def fetch():
        return requests.get(BASE_URL + "?limit=20", headers=HEADERS).json()

    def delete_message(msg_id):
        requests.delete(
            f"{BASE_URL}/{msg_id}",
            headers=HEADERS
        )

if __name__ == "__main__":
    print(f"{tlm()} Start of program.")
    logger = logger() # créer le logger

    # Logging system info
    logger.log(f"CryptoScord - V{version}.", v=True, Wh=True, mention=False)

    # ================= CONFIG =================
    TOKEN = input("Token: ").strip()
    CHANNEL = input("Channel ID: ").strip()
    sub.run("cls" if os.name == "nt" else "clear", shell=True)

    HEADERS = {"Authorization": TOKEN}
    BASE_URL = f"https://discord.com/api/v9/channels/{CHANNEL}/messages"


    # ================= INIT CRYPTO =================
    rsa_priv, rsa_pub = gen_rsa()
    my_pub_b64 = rsa_pub_to_b64(rsa_pub)
    my_fp = rsa_fingerprint(rsa_pub)

    peer_pub = None
    peer_fp = None

    aes = None
    aes_sent = False

    seen = set()
    my_message_ids = []

    # Envoi automatique de la clé RSA
    send(f"[KEY_RSA:{my_fp}]{my_pub_b64}")

    # ================= INPUT THREAD =================
    def input_loop():
        global aes
        while True:
            if not aes:
                time.sleep(1)
                continue

            msg = input("> ")

            if msg.lower() == "exit":
                logger.log(f"Deleting all your messages...", v=True, Wh=True, mention=False)
                for mid in my_message_ids:
                    delete_message(mid)
                    time.sleep(5)  # RATE LIMIT SAFE

                # wipe mémoire (bonus sécurité)
                try:
                    del aes
                    del rsa_priv
                except:
                    pass

                logger.log(f"End Of program.", v=True, Wh=True, mention=False)
                os._exit(0)

            send(f"[MSG]{aes.enc(msg)}")

    threading.Thread(target=input_loop, daemon=True).start()

    # ================= MAIN LOOP =================
    while True:
        try:
            messages = fetch()

            for m in reversed(messages):
                if m["id"] in seen:
                    continue
                seen.add(m["id"])

                content = m["content"]

                # -------- RSA PUBLIC KEY --------
                if content.startswith("[KEY_RSA:"):
                    fp = content[9:25]
                    pub_b64 = content[26:]

                    if fp != my_fp and not peer_pub:
                        peer_pub = rsa_pub_from_b64(pub_b64)
                        peer_fp = fp
                        logger.log(f"RSA key received", v=True, Wh=True, mention=False)

                # -------- AES KEY --------
                elif content.startswith("[KEY_AES:") and not aes:
                    fp = content[9:25]
                    if fp == my_fp:
                        aes_key = rsa_decrypt(rsa_priv, content[26:])
                        aes = AES(aes_key)
                        logger.log(f"AES key received, your session is now active", v=True, Wh=True, mention=False)

                # -------- CHAT --------
                elif content.startswith("[MSG]") and aes:
                    try:
                        logger.log(f"[{m['author']['username']}] {aes.dec(content[5:])}", v=True, Wh=True, mention=False)
                    except:
                        pass

            # -------- SEND AES (1 SEULE FOIS) --------
            if peer_pub and not aes_sent and not aes:
                aes_key = os.urandom(32)
                send(f"[KEY_AES:{peer_fp}]{rsa_encrypt(peer_pub, aes_key)}")
                aes = AES(aes_key)
                aes_sent = True
                logger.log(f"AES key sent, your session is now active", v=True, Wh=True, mention=False)

            time.sleep(15)  # SAFE POLLING
        except KeyboardInterrupt:
            logger.log(f"Deleting all your messages...", v=True, Wh=True, mention=False)
            for mid in my_message_ids:
                delete_message(mid)
                time.sleep(5)  # RATE LIMIT SAFE
            # wipe mémoire (bonus sécurité)
            try:
                del aes
                del rsa_priv
            except:
                pass
            logger.log(f"End Of program.", v=True, Wh=True, mention=False)
            os._exit(0)
            break
