from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64

def encrypting(file, public_key):
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    file = zlib.compress(file)
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  b""

    while not end_loop:
        chunk = file[offset:offset + chunk_size]
        if len(chunk) < chunk_size !=0:
            end_loop = True
        encrypted += rsa_key.encrypt(chunk)
        offset += chunk_size

    return base64.b64encode(encrypted)