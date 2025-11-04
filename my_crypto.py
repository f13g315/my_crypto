from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

REQUIRE_IV_NONCE = ["CBC", "CTR", "CFB", "OFB"]
REQUIRE_PAD = ["ECB", "CBC"] 
MODES = {"ECB": AES.MODE_ECB, "CBC": AES.MODE_CBC, "CTR": AES.MODE_CTR, "CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB,} 

''' 
Created by f13g315
Published 3 Nov 2025
'''

def cipher_choice():
    while True:
        choice = input("Cipher to use (Choices are AES, ChaCha20, or RSA): ").upper()
        if choice in ["AES", "CHACHA20", "RSA"]:
            return choice
        else:
            print("ERROR: Invalid choice. Please choose AES, ChaCha20, or RSA.")
            

def aes_choice():
    while True:
        mode = input("AES mode (ECB/CBC/CTR/CFB/OFB): ").upper()
        if mode in MODES:
            return mode 
        else:
            print(f"ERROR: Invalid mode given. Choose from {list(MODES.keys())}.")


def gen_key_pair():
    prk_file = input("\nEnter filename to store the private key: ")
    passphrase = input("Enter passphrase to protect the private key: ")
    puk_file = input("Enter filename to store the public key: ")
    
    while True:
        key_size = int(input("Enter key size: ")) # Must be multiple of 1024
        if key_size < 1024 or key_size % 1024 != 0: 
            print("ERROR: Key size must be a multiple of 1024.\n")
            continue
        break
            
    key = RSA.generate(key_size)
    if passphrase:
        enc_key = key.export_key(passphrase=passphrase, pkcs = 8, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC') # Recommended protection value
    else:
        enc_key = key.export_key(pkcs=8)

    with open(prk_file, 'wb') as k:
        k.write(enc_key)

    pub_key = key.publickey().export_key()
    with open(puk_file, 'wb') as k:
        k.write(pub_key)

    print(f"\nRSA keypair generated successfully.\nPrivate key saved to '{prk_file}'Public key saved to '{puk_file}'\n")


def symmetric_encryption(choice, input_file, output_file):
    key = get_random_bytes(16)
    try:
        with open(input_file, 'rb') as i:
            plaintext = i.read()

        if choice == 'AES':
            mode = aes_choice()
            operation = MODES[mode]
                             
            if mode in REQUIRE_PAD:
                plaintext = pad(plaintext, AES.block_size)

            if mode == "CTR":
                iv_nonce = get_random_bytes(AES.block_size // 2)
                cipher = AES.new(key, operation, nonce=iv_nonce)
            elif mode in REQUIRE_IV_NONCE:
                iv_nonce = get_random_bytes(AES.block_size)
                cipher = AES.new(key, operation, iv=iv_nonce)
            else:
                cipher = AES.new(key, operation)
            
            ciphertext = cipher.encrypt(plaintext)

        else:
            cipher = ChaCha20.new(key=key, nonce=iv_nonce)
            ciphertext = cipher.encrypt(plaintext)
    
        with open(output_file, 'wb') as e:
            e.write(key)
            if iv_nonce:
                e.write(iv_nonce)
            e.write(ciphertext) 
        
        print(f"\nEncryption successful using {choice}{' ' + mode if mode else ''} mode.\nOutput saved to '{output_file}'.\n")

    except FileNotFoundError:
        print(f"ERROR: File '{input_file}' not found.\n")


def rsa_encryption(input_file, output_file, key_file):
    try:
        with open(input_file, 'rb') as i:
            plaintext = i.read()

        with open(key_file, 'rb') as k:
            pub_key = RSA.import_key(k.read())

        cipher = PKCS1_OAEP.new(pub_key) 
        ciphertext = cipher.encrypt(plaintext) 

        with open(output_file, 'wb') as e:
            e.write(ciphertext)
        
        print(f"\nEncryption successful using RSA mode.")
        print(f"Output saved to '{output_file}'.\n")

    except FileNotFoundError:
        print(f"ERROR: File '{input_file}' not found.\n")


def symmetric_decryption(choice, input_file, output_file):
    try:
        if choice == 'AES':
            mode = aes_choice()
            operation = MODES[mode]

            with open(input_file, 'rb') as e:
                key = e.read(AES.block_size)

                if mode == "CTR":
                    iv_nonce = e.read(AES.block_size // 2)
                    ciphertext = e.read()
                    cipher = AES.new(key, operation, nonce=iv_nonce)
                elif mode in REQUIRE_IV_NONCE:
                    iv_nonce = e.read(AES.block_size)
                    ciphertext = e.read()
                    cipher = AES.new(key, operation, iv=iv_nonce)
                else:
                    ciphertext = e.read()
                    cipher = AES.new(key, operation)

            plaintext = cipher.decrypt(ciphertext)
            if mode in REQUIRE_PAD:
                plaintext = unpad(plaintext, AES.block_size)

        else:
            with open(input_file, 'rb') as e:
                key = e.read(ChaCha20.key_size)
                iv_nonce = e.read(8) # 8 bit nonce
                ciphertext = e.read()
                cipher = ChaCha20.new(key=key, nonce=iv_nonce)
                plaintext = cipher.decrypt(ciphertext)

        with open(output_file, 'wb') as d:
            d.write(plaintext)

        print(f"\nDecryption successful using {choice} {mode if mode else ''} mode.")
        print(f"Plaintext saved to '{output_file}'.\n")

    except FileNotFoundError:
        print("ERROR: Input file not found.\n")


def rsa_decryption(input_file, output_file, key_file):
    passphrase = input("Enter passphrase for the private key (press enter if none): ") or None
    try:
        with open(input_file, 'rb') as e:
            ciphertext = e.read()

        with open (key_file, 'rb') as k:
            private_key = RSA.import_key(k.read(), passphrase=passphrase)

        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        with open(output_file, 'wb') as d:
            d.write(plaintext)

        print(f"\nDecryption successful using RSA mode.")
        print(f"Plaintext saved to '{output_file}'.\n")

    except FileNotFoundError:
        print("ERROR: Input or Key file not found.\n")
    except ValueError:
        print("ERROR: Decryption failed. Check key file or passphrase.\n")


def encrypt():
    input_file = input("\nName of the file to encrypt: ") 
    output_file = input("Name of the output file: ")
    choice = cipher_choice() 
    if choice == 'RSA':
        key_file = input("Enter filename of the public key for encryption: ")
        rsa_encryption(input_file, output_file, key_file)
    else:
        symmetric_encryption(choice, input_file, output_file)


def decrypt():
    input_file = input("\nName of the file to decrypt: ")
    output_file = input("Name of the output file: ")
    choice = cipher_choice()
    if choice == 'RSA':
        key_file = input("Enter filename of the private key for decryption: ")
        rsa_decryption(input_file, output_file, key_file)
    else:
        symmetric_decryption(choice, input_file, output_file)


def main():
    while True:
        func = input("Enter G to generate an RSA Keypair\nEnter E to encrypt a file\nEnter D to decrypt a file\nEnter Q to quit the program\n").upper()
        if func == 'G':
            gen_key_pair()
        elif func == 'E':
            encrypt()
        elif func == 'D':
            decrypt()
        elif func == 'Q':
            break
        else:
            print("\nInvalid response!\n")
            
        
if __name__ == "__main__":
    main()

