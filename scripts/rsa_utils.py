import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def gen_rsa():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    return priv, priv.public_key()

def rsa_pub_to_b64(pub):
    return base64.b64encode(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()

def rsa_pub_from_b64(data):
    return serialization.load_pem_public_key(base64.b64decode(data))

def rsa_encrypt(pub, data: bytes) -> str:
    return base64.b64encode(
        pub.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    ).decode()

def rsa_decrypt(priv, data: str) -> bytes:
    return priv.decrypt(
        base64.b64decode(data),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_fingerprint(pub) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(raw).hexdigest()[:16]
