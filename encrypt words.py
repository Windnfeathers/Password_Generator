from cryptography.fernet import Fernet
from pathlib import Path
import csv
import sys


# Base directory = folder where this script lives
BASE_DIR = Path(__file__).resolve().parent

WORDS_PATH = BASE_DIR / "words.csv"
KEY_PATH = BASE_DIR / "key.key"
ENC_WORDS_PATH = BASE_DIR / "encrypted_words.csv"


def load_words(path: Path = WORDS_PATH) -> list[str]:
    """
    Load words from a CSV file.
    - Uses the first non-empty cells in each row as words.
    - Ignores blank cells/lines.
    """
    if not path.exists():
        print(f"ERROR: Could not find {path}. Put your word list there as 'words.csv'.", file=sys.stderr)
        sys.exit(1)

    words: list[str] = []

    with path.open(newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            for cell in row:
                w = cell.strip()
                if w:
                    words.append(w)

    if not words:
        print(f"ERROR: No words found in {path}.", file=sys.stderr)
        sys.exit(1)

    return words


def get_cipher(key_path: Path = KEY_PATH, force_new: bool = False) -> Fernet:
    """
    Load an existing Fernet key from key_path, or generate a new one.
    - If force_new is True, always generate a new key.
    - Otherwise, reuse the existing key if it exists.
    """
    if key_path.exists() and not force_new:
        key = key_path.read_bytes()
        print(f"Using existing key at {key_path}")
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        if key_path.exists():
            print(f"Generated NEW key at {key_path}")
        else:
            print(f"ERROR: Failed to write key to {key_path}", file=sys.stderr)
            sys.exit(1)

    return Fernet(key)


def encrypt_words(words: list[str], cipher: Fernet, out_path: Path = ENC_WORDS_PATH) -> None:
    """
    Encrypt each word and write one encrypted token per line to out_path.
    """
    with out_path.open("wb") as enc_file:
        for word in words:
            token = cipher.encrypt(word.encode("utf-8"))
            enc_file.write(token + b"\n")

    print(f"Encrypted {len(words)} words to {out_path}")


def main():
    # Optional flag: --new-key forces generation of a new key
    force_new = "--new-key" in sys.argv

    words = load_words()
    cipher = get_cipher(force_new=force_new)
    encrypt_words(words, cipher)

    print("\nDone.")
    print(f"- Word list source : {WORDS_PATH}")
    print(f"- Key file         : {KEY_PATH}")
    print(f"- Encrypted output : {ENC_WORDS_PATH}")
    if force_new:
        print("NOTE: You generated a NEW key; any old encrypted_words.csv made with a previous key will no longer work.")


if __name__ == "__main__":
    main()
