"""
Word List Encryption Utility
-----------------------------
Use this script to generate your own encrypted word list for use with the Password Generator.

Instructions:
1. Create a plain text file named 'wordlist.txt' with one word per line.
2. Run this script in the same directory as your wordlist.txt file.
3. Two files will be generated:
   - encrypted_words.csv  -- your encrypted word list
   - key.key              -- the encryption key required by the password generator
4. Place both files in the same directory as the Password Generator before running it.

Note: A new key is generated every time you run this script. If you regenerate
your encrypted word list you must use the new key.key file with it.
"""


import secrets
from cryptography.fernet import Fernet


def generate_encrypted_word_list(input_file, output_file, key_file):
    """
    Read a plain text word list and encrypt it using Fernet symmetric encryption.
    One word per line in the input file.
    """
    # Generate a new encryption key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    # Read the plain text word list
    try:
        with open(input_file, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Could not find input file '{input_file}'")
        return

    if not words:
        print("Error: Word list is empty.")
        return

    # Write encrypted words to output file
    with open(output_file, 'wb') as enc_file:
        for word in words:
            encrypted_word = cipher_suite.encrypt(word.encode())
            enc_file.write(encrypted_word + b'\n')

    # Save the key
    with open(key_file, 'wb') as kf:
        kf.write(key)

    print(f"Done. {len(words)} words encrypted.")
    print(f"Encrypted word list saved to: {output_file}")
    print(f"Key saved to: {key_file}")
    print("Keep your key.key file safe -- you need it to run the password generator.")


if __name__ == "__main__":
    generate_encrypted_word_list(
        input_file="wordlist.txt",
        output_file="encrypted_words.csv",
        key_file="key.key"
    )
