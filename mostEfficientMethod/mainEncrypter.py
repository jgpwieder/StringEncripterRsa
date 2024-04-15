from mostEfficientMethod.rsaEncrypter import encryptEfficiently, generateRsaKeys, decryptEfficiently, readKeys, \
    readFile, getPrivateKeyBytes, getPublicKeyBytes

message = ""

privateKeyFileName = "myPrivateKey.pem"
publicKeyFileName = "myPublicKey.pem"
encryptedFileName = "encryptedData.txt"

try:
    privateKey, publicKey = readKeys(privateKeyFileName=privateKeyFileName, publicKeyFileName=publicKeyFileName)
except:
    privateKey, publicKey = None, None

if not publicKey or not privateKey:
    print("Creating new keys")
    privateKey, publicKey = generateRsaKeys(
        privateKeyFileName=privateKeyFileName,
        publicKeyFileName=publicKeyFileName,
        publicExponent=65537,
        keySize=8192,
    )

base64EncryptedString = encryptEfficiently(
    message=message,
    publicKey=publicKey,
    encryptedFileName=encryptedFileName,
)
print("base64EncryptedString", base64EncryptedString)

# CHECK DATA
decryptedMessage = decryptEfficiently(
    privateKey=privateKey,
    base64EncryptedString=base64EncryptedString,
)
print("decryptedMessage", decryptedMessage)
if decryptedMessage != message:
    raise Exception("message did not match decrypted message")

# CHECK FILE DATA
filePrivateKey, filePublicKey = readKeys(privateKeyFileName=privateKeyFileName, publicKeyFileName=publicKeyFileName)

publicKeyContent = getPublicKeyBytes(publicKey=publicKey).decode()
filePublicKeyContent = getPublicKeyBytes(publicKey=filePublicKey).decode()
if publicKeyContent != filePublicKeyContent:
    print("publicKeyContent", publicKeyContent, "type(publicKeyContent)", type(publicKeyContent))
    print("filePublicKeyContent", filePublicKeyContent, "type(filePublicKeyContent)", type(filePublicKeyContent))
    raise Exception("Public keys are not the same")

privateKeyContent = getPrivateKeyBytes(privateKey=privateKey).decode()
filePrivateKeyContent = getPrivateKeyBytes(privateKey=filePrivateKey).decode()
if privateKeyContent != filePrivateKeyContent:
    print("privateKeyContent", privateKeyContent, "type(privateKeyContent)", type(privateKeyContent))
    print("filePrivateKeyContent", filePrivateKeyContent, "type(filePrivateKeyContent)", type(filePrivateKeyContent))
    raise Exception("Private keys are not the same")

fileBase64EncryptedString = readFile(messageFileName=encryptedFileName)
if fileBase64EncryptedString != base64EncryptedString:
    print("base64EncryptedString", base64EncryptedString, "type(base64EncryptedString)", type(base64EncryptedString))
    print("fileBase64EncryptedString", fileBase64EncryptedString, "type(fileBase64EncryptedString)", type(fileBase64EncryptedString))
    raise Exception("base 64 encoded strings are different")

fileDecryptedMessage = decryptEfficiently(
    privateKey=filePrivateKey,
    base64EncryptedString=fileBase64EncryptedString,
)
print("fileDecryptedMessage", fileDecryptedMessage)
if fileDecryptedMessage != message:
    print("message", message, "type(message)", type(message))
    print("fileDecryptedMessage", fileDecryptedMessage, "type(fileDecryptedMessage)", type(fileDecryptedMessage))
    raise Exception("message did not match FILE decrypted message")
