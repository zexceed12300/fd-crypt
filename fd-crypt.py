from src import encrypt, decrypt
from src import keygen
from progress.bar import ShadyBar
import getpass
import argparse
import time
import sys
import os

path = ""
files_list = ""
key = ""
generate = []
limit = 100000
source = []
_src_count = 0

def crypt_dir():
    with ShadyBar('LOADING SOURCE ', fill='#', suffix='%(index)d/{} FILE'.format(str(limit)), max=limit) as bar:
        global path
        for r, d, f in os.walk(path):
            for file in f:
                global _src_count
                if limit == _src_count:
                    break
                bar.next(1)
                _src_count += 1
                source.append(os.path.join(r, file))
        print("")
time.sleep(1)

def crypt_list():
    with ShadyBar('LOADING SOURCE ', fill='#', suffix='%(index)d/{} FILE'.format(str(limit)) , max=limit) as bar:
        global files_list
        list = open(files_list, "r").readlines()
        for i in list:
            global _src_count
            if limit ==_src_count:
                break
            bar.next(1)
            _src_count += 1
            source.append(i.strip())
        print("")
time.sleep(1)

def genkey():
    password = getpass.getpass("Passphrase : ")
    confirm = getpass.getpass("Confirm passphrase : ")
    if password==confirm:
        try:
            print("")
            keygen.RSAKEY(int(generate[0]), passphrase=confirm, salt=str(generate[1]))
            open("key/public_key.pem","wb").write(keygen.public_key)
            open("key/private_key.pem", "wb").write(keygen.private_key)
            print("")
            print("EXPORTED KEY DETAILS :")
            print("Lenght: {} bit".format(generate[0]))
            print("Salt: {}".format(generate[1]))
            print("Pass: {}\n".format("*"*len(confirm)))
            print("PUBKEY/PRVKEY EXPORTED TO ./key")
            sys.exit()
        except ValueError:
            print("\nfd-crypt: RSA modulus length must be a multiple of 256 and > 1024")
            sys.exit()
    else:
        print("fd-crypt: Wrong passphrase!, please try again.")
        sys.exit()

def begin_encrypting():
    print("EXECUTING ENCRYPTIONS OPERATIONS\n")
    global source
    if path=="":
        crypt_list()
    else:
        crypt_dir()
    print("LOCATING TARGET FILES.")
    public_key = open(key, "r").read()
    print("BEGINNING ENCRIPTION OPERATIONS")
    time.sleep(1)
    _file_error = ""
    _file_error_count = 0
    for l in source:
        try:
            unecnrypted_file = open(l, "rb").read()
            print("Encrypting {}".format(l))
            encrypted_file = encrypt.encrypting(unecnrypted_file, public_key)
            file = open(l+".enc", "wb")
            file.write(encrypted_file)
            file.close()
            os.remove(l)
        except FileNotFoundError:
            _file_error += l+" => file not found/error!"+"\n"
            _file_error_count += 1
            print("Skipping {} => file not found/error!".format(l))
            continue
        except TypeError:
            print("\nfd-crypt: encryption: Invalid PUBLIC_KEY!")
            sys.exit()
    print("ENDED ENCRIPTION OPERATIONS.\n")
    open("./log/encrypted_fail.txt", "w").write(str(_file_error+"\n"))
    enclist = open("./log/encrypted_list.txt", "w")
    for l in source:
        enclist.write(l + "\n")
    print("ENCRYPTION RESULT :")
    print("Total Encrypted: {} file | result => ./encrypted_list.txt".format(_src_count - _file_error_count))
    print("Total Failed: {} file | result => ./fail_result.txt".format(_file_error_count))
    sys.exit()

def begin_decrypting():
    print("EXECUTING DECRYPTION OPERATIONS\n")
    if path=="":
        crypt_list()
    else:
        crypt_dir()
    print("LOCATING TARGET FILES.")
    private_key = open(key, "r").read()
    print("BEGINNING DECRIPTION OPERATIONS")
    time.sleep(1)
    _file_error = ""
    _file_error_count = 0
    for l in source:
        try:
            encrypted_file = open(l, "rb").read()
            decrypted_file = decrypt.decrypting(encrypted_file, private_key)
            print("Decrypting {}".format(l))
            fn = l.replace(".enc","")
            f = open(fn, "wb")
            f.write(decrypted_file)
            f.close()
            os.remove(l)
        except FileNotFoundError:
            _file_error += l+" => file not found/error!"+"\n"
            _file_error_count += 1
            print("Skipping {} => file not found/error!".format(l))
            continue
        except TypeError:
            print("\nfd-crypt: decryption: Invalid PRIVATE_KEY!")
            sys.exit()
        except ValueError:
            _file_error += l + " => unencrypted files!" + "\n"
            _file_error_count += 1
            print("Skipping {} => unencrypted files!".format(l))
            continue
    print("ENDED DECRIPTION OPERATIONS.\n")
    open("./log/decrypted_fail.txt", "w").write(str(_file_error + "\n"))
    declist = open("./log/decrypted_list.txt", "w")
    for l in source:
        declist.write(l + "\n")
    print("DECRYPTION RESULT :")
    print("Total Decrypted: {} file | result => ./log/decrypted_list.txt".format(_src_count - _file_error_count))
    print("Total Failed: {} file | result => ./log/decrypted_fail.txt".format(_file_error_count))
    sys.exit()

def get_parameters():
    parser = argparse.ArgumentParser()
    parser.add_argument("--encrypt-dir", metavar="[path]", help="encrypt all files in specified directory/folder (ex: --encrypt-dir /directory/to/encrypt)")
    parser.add_argument("--decrypt-dir", metavar="[path]", help="decrypt all encrypted files in specifed directory/folder (ex: --decrypt-dir /directory/to/decrypt)")
    parser.add_argument("--encrypt-list", metavar="[pathlist]", help="encrypt all files based on a list of file paths (ex: --encrypt-list pathlist.txt)", )
    parser.add_argument("--decrypt-list", metavar="[pathlist]", help="decrypt all files based on a list of file paths (ex: --decrypt-list pathlist.txt)")
    parser.add_argument("--rsakey", metavar="[pubkey/prvkey]", help="path to your public_key(for encryption) or private_key(for decryption) (ex: --rsakey key/public_key.pem)")
    parser.add_argument("--generate", nargs=2, metavar=("[lenght]","[salt]"), help="generate RSA publickey/privatekey with salt and passphrase (ex: --keygen 4096 salt123)")
    parser.add_argument("--limit", metavar="[total files]", default=100000, help="limiting amount of files to be encrypted or decrypted (ex: --limit 90) (default: 100000)")
    args = parser.parse_args()

    global path
    if args.encrypt_dir:
        path = str(args.encrypt_dir)
    if args.decrypt_dir:
        path = str(args.decrypt_dir)
    global files_list
    if args.encrypt_list:
        files_list = str(args.encrypt_list)
    if args.decrypt_list:
        files_list = str(args.decrypt_list)
    global key
    if args.rsakey:
        key = str(args.rsakey)
    global generate
    if args.generate:
        generate = args.generate
        genkey()
    global limit
    if args.limit:
        limit = int(args.limit)

    if args.encrypt_dir:
        if os.path.isdir(path):
            pass
        else:
            print("fd-crypt: encrypt-dir: No such directory/folder!, read --help/-h")
            sys.exit()
        if args.decrypt_dir:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.encrypt_list:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.decrypt_list:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
        if args.rsakey:
            pass
        else:
            print("fd-crypt: public_key not found!, read --help/-h")
            sys.exit()
        begin_encrypting()

    if args.decrypt_dir:
        if os.path.isdir(path):
            pass
        else:
            print("fd-crypt: decrypt-dir: No such directory/folder!, read --help/-h")
            sys.exit()
        if args.encrypt_dir:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.encrypt_list:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.decrypt_list:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
        if args.rsakey:
            pass
        else:
            print("fd-crypt: private_key not found!, read --help/-h")
            sys.exit()
        begin_decrypting()

    if args.encrypt_list:
        if os.path.isfile(files_list):
            pass
        else:
            print("fd-crypt: encrypt-list: file list not found!, read --help/-h")
            sys.exit()
        if args.decrypt_list:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
        if args.encrypt_dir:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.decrypt_dir:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.publickey:
            pass
        else:
            print("fd-crypt: public_key not found!, read --help/-h")
            sys.exit()
        begin_encrypting()

    if args.decrypt_list:
        if os.path.isfile(files_list):
            pass
        else:
            print("fd-crypt: decrypt-list: file list not found!, read --help/-h")
            sys.exit()
        if args.encrypt_list:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
        if args.encrypt_dir:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.decrypt_dir:
            print("fd-crypt: multiple crypto operations!, read --help/-h")
            sys.exit()
        if args.privatekey:
            pass
        else:
            print("fd-crypt: private_key not found!, read --help/-h")
            sys.exit()
        begin_decrypting()

    parser.print_help()

get_parameters()