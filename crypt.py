import sys
import os
from Crypto.Cipher import AES
import base64

def pad(message: bytes) -> bytes:
    block_size = 16
    padding = block_size - len(message) % block_size
    return message + (chr(padding) * padding).encode()



def unpad(message: bytes) -> bytes:
    padding = ord(message[-1:])
    return message[:-padding]


def encrypt(message: bytes, key: bytes) -> bytes:
    message = pad(message)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(message)
    return base64.b64encode(encrypted_message)


def decrypt(encrypted_message: bytes, key: bytes) -> bytes:
    encrypted_message = base64.b64decode(encrypted_message)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message)
    return unpad(decrypted_message)


def get_public_key(file_name: str) -> dict:
    try:
        with open(file_name) as pu:
            public = pu.read()
            pu.close()      # Read file
        public = base64.b64decode(public).decode('utf-8')      # Decode
        pu_key = public.split(',')
        dic = {'N': int(pu_key[0], 16), 'e': int(pu_key[1], 16)} # Get N and e for RSA key
        return dic
    except:
        print("Unexpected Public Key")
        os.close()

def get_private_key(file_name: str) -> dict:
    try:
        with open(file_name) as pr:
            private = pr.read()
            pr.close()      # Read file
        private = base64.b64decode(private).decode('utf-8')      # Decode
        pr_key = private.split(',')
        dic = {'p': int(pr_key[0], 16), 'q': int(pr_key[1], 16), 'd': int(pr_key[2], 16)}
                                                    # Get p,q and d for RSA key
        return dic
    except:
        print("Unexpected Private Key")
        os.close()


def encrypt_master(public_key_file: str, input_file: str, output: str) -> str:
    # Get public key, generate AES key, and encrypting by RSA
    try:
        pub = get_public_key(public_key_file)
        aes_key = os.urandom(16)
        aes_key_for_rsa = int.from_bytes(aes_key, 'little')
        cipher_aes_key = pow(aes_key_for_rsa, pub['e'], pub['N'])
    except:
        return "Invalid public key file"

    try:
        with open(input_file) as f:
            message = f.read().encode('utf-8')
            f.close()
        encrypted_message = encrypt(message, aes_key)
        cipher_text = base64.b64encode(encrypted_message).decode('utf-8') + '1ACF07==7983478A' + hex(cipher_aes_key)

        f = open(output, 'w')
        f.write(base64.b64encode(cipher_text.encode('utf-8')).decode('utf-8'))
        f.close()
    except:
        return "Cannot access input/output message OR message include non-ascii"
    return "Encryption Succeed !"


def decrypt_master(private_key_file: str, cipher_file: str, output_file: str) -> str:
    try:
        with open(cipher_file) as f:
            cipher = f.read()
            f.close()           # Read file
        cipher = base64.b64decode(cipher.encode('utf-8')).decode('utf-8') # decode
        cipher_aes = cipher.split("1ACF07==7983478A0x")[0]
        cipher_rsa = cipher.split("1ACF07==7983478A0x")[1]     # Split AES cipher and Key
        cipher_rsa = int(cipher_rsa, 16)

        prv_key = get_private_key(private_key_file)     # Get RSA key
        plain_ras = pow(cipher_rsa, prv_key['d'], (prv_key['p'] * prv_key['q']) )
        plain_aes_key = plain_ras.to_bytes(16, "little")    # AES key

        cipher_aes = base64.b64decode(cipher_aes)       # AES cipher text base64 decode
        plaintext = decrypt(cipher_aes, plain_aes_key).decode('utf-8')      # AES decryption
    except:
        return "Unexpected cipher file"
    # Dump
    f = open(output_file, 'w')
    f.write(plaintext)
    return "Decryption Succeed !"


if __name__ == '__main__':
    if '-e' == sys.argv[1]:
        try:
            print(encrypt_master(sys.argv[2], sys.argv[3], sys.argv[4]))
        except:
            print("instruction error")
    elif '-d' == sys.argv[1]:
        try:
            print(decrypt_master(sys.argv[2], sys.argv[3], sys.argv[4]))
        except:
            print("instruction error")
    else:
        print("invalid instruction")