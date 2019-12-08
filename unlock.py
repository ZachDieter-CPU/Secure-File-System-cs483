from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import argparse
import os

def addParser():
    parser = argparse.ArgumentParser(description="Simple File System Encryption")
    parser.add_argument("-d", dest="file1", required=True, help="The directory to lock or unlock",metavar="KeyFile")
    parser.add_argument("-p", dest="file2", required=False, help="The path to the public key for the locking party to unlock mode, and the public key of the unlocking party in lock mode",metavar="MessageFile")
    parser.add_argument("-r", dest="file3", required=False, help="The path to the private key that can decrypt the keyfile in unlock mode or that will be used to sign the keyfile in lock mode",metavar="OutputFile")
    parser.add_argument("-s", dest="file4", required=False, help="For lock this is the subject you want to encrypt the directory for, for unlock the subject you expect the directory to be from",metavar="OutputFile")
    return parser

def DecryptKey(ciphertext, path):
    with open("keypriv.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
           f.read(),
           password=None,
           backend=default_backend() 
        )
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

def VerfySign(key, message, path):
    with open('eckeypub.pem', "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
        public_key.verify(
            key,
            message,
            ec.ECDSA(hashes.SHA256())
        )

def main():
    #Parser for input
    parser = addParser()
    args = parser.parse_args()
    rootDir = args.file1

    PathforKeyfileKey = args.file3
    subject = args.file4

    #Use this to encrypt stuff
    keyFile = rootDir + "\keyfile"
    keyFileSig = rootDir + "\keyfile.sig"
    ivPath = rootDir + "\IV"

    #check sig of keyfile.sig
    encryptKey = None
    encryptKeySig = None

    with open(keyFile, 'rb') as f:
        encryptKey = f.read()
        print(encryptKey)

    with open(keyFileSig, "rb") as f:
        encryptKeySig = f.read()

    VerfySign(encryptKeySig, encryptKey, "")

    #Creating Encryption Mode
    key = DecryptKey(encryptKey, "")
    iv = open(ivPath, 'rb').read()

    #Dir traversal
    aesgcm = AESGCM(key)

    for dirName, subDirList, fileList in os.walk(rootDir):
        print("Found dir: %s" % dirName)
        for fname in fileList:
            if(fname == "IV" or fname == "keyfile" or fname == "keyfile.sig"):
                print("continue")
                continue
            print('\t%s' % fname)
            with open(os.path.join(dirName, fname), 'br+') as fileContent:
                cipherText = fileContent.read()
                print(cipherText)
                fileContent.seek(0)
                fileContent.truncate(0)
                ct = aesgcm.decrypt(iv, cipherText, None)
                fileContent.write(ct)

if __name__ == "__main__":
    main()