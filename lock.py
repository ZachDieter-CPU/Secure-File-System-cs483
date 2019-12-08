import os
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def addParser():
    parser = argparse.ArgumentParser(description="Simple File System Encryption")
    parser.add_argument("-d", dest="file1", required=True, help="The directory to lock or unlock",metavar="KeyFile")
    parser.add_argument("-p", dest="file2", required=False, help="The path to the public key for the locking party to unlock mode, and the public key of the unlocking party in lock mode",metavar="MessageFile")
    parser.add_argument("-r", dest="file3", required=False, help="The path to the private key that can decrypt the keyfile in unlock mode or that will be used to sign the keyfile in lock mode",metavar="OutputFile")
    parser.add_argument("-s", dest="file4", required=False, help="For lock this is the subject you want to encrypt the directory for, for unlock the subject you expect the directory to be from",metavar="OutputFile")
    return parser


def EncryptKey(key, path):
    #with open(path, "rb") as key_file:
    with open("keypub.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
        ciphertext = public_key.encrypt(
            key, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

def signKeyFile(message, path):
    with open('eckeypriv.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
        sig = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print(sig)
        return sig


def main():
    #Parser for input
    parser = addParser()
    args = parser.parse_args()
    #path
    rootDir = args.file1 
    ivPath = rootDir + "\IV"
    keyPath = rootDir + "\keyfile"
    keySigPath = rootDir + "\keyfile.sig"

    #Creating Encryption Mode
    #Use this to encrypt stuff
    key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    #Dir traversal
    for dirName, subDirList, fileList in os.walk(rootDir):
        print("Found dir: %s" % dirName)
        for fname in fileList:
            print('\t%s' % fname)
            with open(os.path.join(dirName, fname), 'br+') as fileContent:
                plainText = fileContent.read()
                print(plainText)
                fileContent.seek(0)
                fileContent.truncate(0)
                ct = aesgcm.encrypt(iv, plainText, None)
                fileContent.write(ct)

    #Write key to file
    kf = open(keyPath, 'wb')
    encryptKey = EncryptKey(key, "")
    kf.write(encryptKey)
    kf.close()
    #sign keyfile
    ksf = open(keySigPath, 'wb')
    ksf.write(signKeyFile(encryptKey, ""))
    ksf.close()
    #Write Iv to file
    ivf = open(ivPath, 'wb')
    ivf.write(iv)
    ivf.close()

if __name__ == "__main__":
    main()
