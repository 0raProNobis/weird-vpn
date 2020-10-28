import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class RSAHelper:

    pubkey = None
    __privkey = None

    @classmethod
    def pub2pem(cls, pubkey):
        pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def pubkey2pem(self):
        pem = self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def pem2key(self, pem: bytes):
        pubkey = serialization.load_pem_public_key(
            pem
        )
        return pubkey

    def generateKeys(self):
        self.__privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pubkey = self.__privkey.public_key()

    def encrypt(self, message: bytes, otherkey: rsa.RSAPublicKey):
        signature = self.__privkey.sign(
            message,
            apadding.PSS(
                mgf=apadding.MGF1(hashes.SHA256()),
                salt_length=apadding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        ciphertext = otherkey.encrypt(
            message,
            apadding.OAEP(
                mgf=apadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return signature + ciphertext

    def decrypt(self, ciphertext: bytes):
        plaintext = self.__privkey.decrypt(
            ciphertext,
            apadding.OAEP(
                mgf=apadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def verify(self, plaintext: bytes, signature, otherkey: rsa.RSAPublicKey):
        otherkey.verify(
            signature,
            plaintext,
            apadding.PSS(
                mgf=apadding.MGF1(hashes.SHA256()),
                salt_length=apadding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def dumpprivkey(self):
        pem = self.__privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem

    def loadfromprivpem(self, pem):
        self.__privkey = serialization.load_pem_private_key(
            pem,
            password=None
        )
        self.pubkey = self.__privkey.public_key()

class AESHelper:

    __key = None

    def setkey(self, key):
        self.__key = key

    def __pad(self, message: bytes):
        padder = padding.PKCS7(len(self.__key)*8).padder()
        padded_message = padder.update(message)
        padded_message += padder.finalize()
        return padded_message

    def __unpad(self, message: bytes):
        unpadder = padding.PKCS7(len(self.__key)*8).unpadder()
        unpadded_message = unpadder.update(message)
        unpadded_message += unpadder.finalize()
        return unpadded_message

    def encrypt(self, message: bytes):
        blockdiff = len(message) % len(self.__key )
        if blockdiff != 0:
            message = self.__pad(message)
        iv= os.urandom(16)
        cipher = Cipher(algorithms.AES(self.__key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipherText = encryptor.update(message) + encryptor.finalize()
        ivAndCipherText = iv + cipherText
        return ivAndCipherText

    def decrypt(self, crypto: bytes):
        iv = crypto[0:16]
        ciphertext = crypto[16:]
        cipher = Cipher(algorithms.AES(self.__key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.__unpad(plaintext)
        return plaintext


class ECHelper:

    pubkey = None
    sharedkey = None
    derivedkey = None
    __privkey = None

    def __init__(self):
        pass

    def generatekeys(self):
        self.__privkey = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pubkey = self.__privkey.public_key()

    @property
    def pubkey(self):
        public_bytes = self.__pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        public_str = public_bytes.decode()
        return public_str

    @pubkey.setter
    def pubkey(self, key):
        self.__pubkey = key

    def pem2key(self, pem: bytes):
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def generatesharedkey(self, pem: bytes):
        self.sharedkey = self.__privkey.exchange(ec.ECDH(), self.pem2key(pem))
        self.derivedkey = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'key exchange'
        ).derive(self.sharedkey)

    def encrypt(self, message):
        signature = rsa.sign(message, self.__privkey, 'SHA-1')
        crypto = rsa.encrypt(message, pubkey)

        return crypto, signature

    def decrypt(self, crypto, signature):
        decryptedMessage = rsa.decrypt(crypto, privkey)
        verified = rsa.verify(decryptedMessage, signature, pubkey)

        return verified, decryptedMessage
