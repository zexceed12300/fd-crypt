from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64

def decrypting(encrypted_file, private_key):
    rsa_key = RSA.importKey(private_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    encrypted_file = base64.b64decode(encrypted_file)
    chunk_size = 512
    offset = 0
    decrypted =  b""

    while offset < len(encrypted_file):
        chunk = encrypted_file[offset:offset + chunk_size]
        decrypted += rsa_key.decrypt(chunk)
        offset += chunk_size

    return zlib.decompress(decrypted)