from mostEfficientMethod.rsaEncrypter import decryptEfficiently, readKeys, readFile


privateKeyFileName = "myPrivateKey.pem"
encryptedFileName = "encryptedData.txt"


fileBase64EncryptedString = readFile(messageFileName=encryptedFileName)
filePrivateKey, _ = readKeys(privateKeyFileName=privateKeyFileName)
fileDecryptedMessage = decryptEfficiently(
    privateKey=filePrivateKey,
    base64EncryptedString=fileBase64EncryptedString,
)
print("fileDecryptedMessage")
print("\"{}\"".format(fileDecryptedMessage))
