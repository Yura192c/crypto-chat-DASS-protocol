import os
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Helper functions for encryption, decryption, and signing

def generate_ec_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def sign_data(private_key, data):
    return private_key.sign(data, ec.ECDSA(Prehashed(hashes.SHA256())))

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(signature, data, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except:
        return False

def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def load_keys_from_files(private_key_file, public_key_file):
    # Загрузка приватного ключа
    with open(private_key_file, 'rb') as priv_file:
        private_key = load_pem_private_key(priv_file.read(), password=None)

    # Загрузка публичного ключа
    with open(public_key_file, 'rb') as pub_file:
        public_key = load_pem_public_key(pub_file.read())

    return private_key, public_key


def save_keys_to_files(private_key, public_key, private_key_file, public_key_file):
    # Сохранение приватного ключа
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Без пароля
        ))

    # Сохранение публичного ключа
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    iv = b'\xfa\xb2@\xc6\xab@mp\x81\x9a\xa2\xc2Dz\xfa\x15'
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    iv = b'\xfa\xb2@\xc6\xab@mp\x81\x9a\xa2\xc2Dz\xfa\x15'
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext
