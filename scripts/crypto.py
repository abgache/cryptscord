import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AES:
    def __init__(self, key: bytes):
        self.key = key

    def enc(self, msg: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self.key).encrypt(nonce, msg.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def dec(self, data: str) -> str:
        raw = base64.b64decode(data)
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(self.key).decrypt(nonce, ct, None).decode()
