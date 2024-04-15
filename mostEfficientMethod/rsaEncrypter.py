import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


def getPrivateKeyBytes(privateKey):
    return privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def getPublicKeyBytes(publicKey):
    return publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generateRsaKeys(privateKeyFileName, publicKeyFileName, publicExponent=65537, keySize=2048):
    privateKey = rsa.generate_private_key(public_exponent=publicExponent, key_size=keySize)
    publicKey = privateKey.public_key()

    with open(privateKeyFileName, "wb") as privateKeyFile:
        privateKeyFile.write(getPrivateKeyBytes(privateKey=privateKey))
    with open(publicKeyFileName, "wb") as publicKeyFile:
        publicKeyFile.write(getPublicKeyBytes(publicKey=publicKey))

    return privateKey, publicKey


def readKeys(privateKeyFileName=None, publicKeyFileName=None, password=None):
    privateKey, publicKey = None, None
    if privateKeyFileName:
        with open(privateKeyFileName, "rb") as privateFile:
            privateKey = serialization.load_pem_private_key(privateFile.read(), password=password)
    if publicKeyFileName:
        with open(publicKeyFileName, "rb") as publicFile:
            publicKey = serialization.load_pem_public_key(publicFile.read())

    return privateKey, publicKey


def readFile(messageFileName):
    with open(messageFileName, "rb") as messageFile:
        return messageFile.read().decode("utf8")


def encryptEfficiently(message, publicKey, encryptedFileName):
    encryptedBytes = publicKey.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(encryptedFileName, "w") as f:
        base64EncryptedString = base64.b64encode(encryptedBytes).decode('utf8')
        f.write(base64EncryptedString)

    return base64EncryptedString


def decryptEfficiently(base64EncryptedString, privateKey):
    encryptedBytes = base64.b64decode(base64EncryptedString)
    return privateKey.decrypt(
        encryptedBytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    ).decode()
