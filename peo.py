#!/usr/bin/env python3
import argparse
from cryptography.fernet import Fernet
import os
import base64
from itertools import cycle

def generate_key(key_file):
    """Generates a key and saves it into a file"""
    key = Fernet.generate_key()
    with open(key_file, "wb") as key_file:
        key_file.write(key)

def load_key(key_file):
    """Loads the previously generated key"""
    return open(key_file, "rb").read()

def obfuscate_data(data, key, insert_dummy_every=10):
    """Obfuscates data by shuffling bytes, inserting dummy data, and XORing with a key-derived sequence"""
    # Generate a pseudo-random sequence from the key
    prng_seed = sum(bytearray(base64.urlsafe_b64decode(key))) % 256
    prng = (prng_seed + i for i in cycle(range(256)))

    # Shuffle data based on prng
    shuffled_data = bytes(data[i] for i in sorted(range(len(data)), key=lambda x: next(prng)))
    
    # Insert dummy bytes
    obfuscated_data = bytearray()
    for i, byte in enumerate(shuffled_data):
        if i % insert_dummy_every == 0:
            obfuscated_data.append(next(prng) & 0xFF)  # Dummy byte
        obfuscated_data.append(byte)
    
    # Simple XOR for an additional layer of obfuscation
    xor_key = prng_seed.to_bytes(1, 'little') * len(obfuscated_data)
    final_data = bytes(a ^ b for a, b in zip(obfuscated_data, xor_key))
    
    return final_data

def deobfuscate_data(data, key, insert_dummy_every=10):
    """Reverses the obfuscation process to retrieve the original data"""
    prng_seed = sum(bytearray(base64.urlsafe_b64decode(key))) % 256
    prng = (prng_seed + i for i in cycle(range(256)))
    
    # Reverse XOR
    xor_key = prng_seed.to_bytes(1, 'little') * len(data)
    data = bytes(a ^ b for a, b in zip(data, xor_key))
    
    # Remove dummy bytes
    data = bytearray(data[i] for i in range(len(data)) if i % (insert_dummy_every + 1) != 0)
    
    # Unshuffle data
    prng = (prng_seed + i for i in cycle(range(256)))
    positions = sorted(range(len(data)), key=lambda x: next(prng))
    original_data = bytearray(len(data))
    for i, pos in enumerate(positions):
        original_data[pos] = data[i]
    
    return bytes(original_data)

def encrypt_file(input_file_name, output_file_name, key):
    """Encrypts and obfuscates a file"""
    fernet = Fernet(key)
    
    with open(input_file_name, "rb") as file:
        file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        obfuscated_data = obfuscate_data(encrypted_data, key)

    with open(output_file_name, "wb") as file:
        file.write(obfuscated_data)

def decrypt_file(input_file_name, output_file_name, key):
    """Deobfuscates and decrypts a file"""
    fernet = Fernet(key)
    
    with open(input_file_name, "rb") as file:
        obfuscated_data = file.read()
        deobfuscated_data = deobfuscate_data(obfuscated_data, key)
        decrypted_data = fernet.decrypt(deobfuscated_data)

    with open(output_file_name, "wb") as file:
        file.write(decrypted_data)

def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a file using Fernet encryption with advanced obfuscation.")
    parser.add_argument("-e", "--encrypt-file", type=str, help="The name of the file to perform the operation on.")
    parser.add_argument("-o", "--output-file", type=str, help="The name of the output file. Defaults to 'output.enc' for encryption or 'output.dec' for decryption if not provided.")
    parser.add_argument("-d", "--decrypt-file", type=str, help="Decrypt the input file. If not specified, the default action is to encrypt.")
    # Add a parser argument to accept a filename for the key file
    parser.add_argument("-k", "--key-file", type=str, default="secret.key", help="The name of the file containing the secret key")
    # Add a parser argument to tell the program to generate a new key
    parser.add_argument("-g", "--generate-key", action="store_true", help="Generate a new secret key and save it to a file")

    args = parser.parse_args()

    # Define a default value of secret.key for key_file if not provided
    #key_file = args.key_file if args.key_file else "secret.key" 

    if args.generate_key:
        generate_key(args.key_file)
        print(f"Generated a new key and saved it to '{args.key_file}'.")
        # Exit the function and finish processing
        return

    key = load_key(args.key_file)  # Ensure a key is already generated

    if args.decrypt_file:
        output_file = args.output_file if args.output_file else "output.dec"
        decrypt_file(args.decrypt_file, output_file, key)
        print(f"Decrypted '{args.decrypt_file}' to '{output_file}'.")
    else:
        output_file = args.output_file if args.output_file else "output.enc"
        encrypt_file(args.encrypt_file, output_file, key)
        print(f"Encrypted '{args.encrypt_file}' to '{output_file}'.")

    

if __name__ == "__main__":
    main()
