from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from progress.bar import ShadyBar
import time

private_key = ""
public_key = ""
def RSAKEY(lenght, passphrase, salt="none"):
    with ShadyBar('GENERATING KEYS', fill='#', suffix='%(percent)d%%') as bar:
        bar.next(33)
        time.sleep(1.1)
        bar.next(33)
        master_key = PBKDF2(bytes(passphrase, "utf-8"), bytes(salt, "utf-8"), count=10000)
        def rand(n):
            rand.i += 1
            return PBKDF2(master_key, bytes(rand.i), dkLen=n, count=1)
        rand.i = 0
        rsa_key = RSA.generate(lenght, randfunc=rand)
        global private_key
        private_key = rsa_key.exportKey("PEM")
        global public_key
        public_key = rsa_key.publickey().exportKey("PEM")
        bar.next(100)