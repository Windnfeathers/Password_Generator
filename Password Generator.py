import os
import sys
import secrets
import string
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox


# ---------------- Core helpers ---------------- #

def read_encrypted_word_list(filename, keyfile):
    """Read and decrypt the word list using Fernet."""
    with open(keyfile, 'rb') as kf:
        key = kf.read()
    cipher_suite = Fernet(key)

    word_list = []
    with open(filename, 'rb') as enc_file:
        for enc_word in enc_file:
            word = cipher_suite.decrypt(enc_word.strip()).decode()
            word_list.append(word)
    return word_list


def secure_choice(seq):
    """Cryptographically secure choice from a sequence."""
    return seq[secrets.randbelow(len(seq))]


def random_case(word: str, low_security: bool = False) -> str:
    """
    Randomize casing of each alphabetic character.
    Low security mode reduces the capitalization rate.
    """
    out_chars = []

    # Probability (percent) of uppercase:
    # Normal: 50%
    # Low security: 15%
    uppercase_percent = 15 if low_security else 50

    for c in word:
        if c.isalpha():
            if secrets.randbelow(100) < uppercase_percent:
                out_chars.append(c.upper())
            else:
                out_chars.append(c.lower())
        else:
            out_chars.append(c)
    return ''.join(out_chars)


def generate_random_word(word_list, low_security: bool = False):
    """Choose a random word and apply random casing."""
    return random_case(secure_choice(word_list), low_security)


def maybe_inject_symbol(word: str, symbols: str) -> str:
    """
    Optionally replace a random character in the word with a symbol.
    This is in addition to any separate symbol/number blocks.
    """
    if not word:
        return word
    # 50% chance to do nothing
    if secrets.randbits(1) == 0:
        return word

    idx = secrets.randbelow(len(word))
    sym = secure_choice(symbols)
    return word[:idx] + sym + word[idx + 1:]


def random_digits(length: int) -> str:
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


def ensure_uppercase(pw: str) -> str:
    """Guarantee at least one uppercase letter in low-security mode."""
    if any(c.isupper() for c in pw):
        return pw
    # Force uppercase into the first alphabetic position
    for i, c in enumerate(pw):
        if c.isalpha():
            return pw[:i] + c.upper() + pw[i+1:]
    return pw


# ---------------- Standard mode (length-controlled) ---------------- #

def generate_password_standard(word_list, low_security: bool = False):
    """
    Generate a password targeting ~12–15 characters, never less than 9.
    Uses exactly 2 words (trimmed), guaranteed at least one symbol,
    and a digit block.
    """
    SYMBOLS = "!@#$%^&*+=?-_."

    # Always use 2 words to control length
    w1 = generate_random_word(word_list, low_security=low_security)
    w2 = generate_random_word(word_list, low_security=low_security)

    # Remove spaces inside words (no spaces in passwords)
    w1 = w1.replace(" ", "")
    w2 = w2.replace(" ", "")

    # Trim long words to keep total length manageable
    def trim_word(w: str) -> str:
        # 6-char cap keeps typical length in the 12–15 range with digits
        return w[:6] if len(w) > 6 else w

    w1 = trim_word(w1)
    w2 = trim_word(w2)

    # Optional symbol injection into each word, but guarantee at least one
    injected_symbol = False

    if secrets.randbits(1):
        w1_new = maybe_inject_symbol(w1, SYMBOLS)
        if w1_new != w1:
            injected_symbol = True
        w1 = w1_new

    if secrets.randbits(1):
        w2_new = maybe_inject_symbol(w2, SYMBOLS)
        if w2_new != w2:
            injected_symbol = True
        w2 = w2_new

    # If no symbol was injected naturally, force one into w1
    if not injected_symbol and w1:
        idx = secrets.randbelow(len(w1))
        sym = secure_choice(SYMBOLS)
        w1 = w1[:idx] + sym + w1[idx + 1:]

    # Shuffle word order
    words = [w1, w2]
    secrets.SystemRandom().shuffle(words)
    w1, w2 = words

    base = w1 + w2
    base_len = len(base)

    # Decide how many digits so total length is at least 9 and at most 15
    if base_len >= 7:
        # 2 or 3 digits works and keeps us within 15 chars in most cases
        digits_len = 2 if secrets.randbits(1) else 3
    elif base_len == 6:
        # Need at least 3 digits to hit 9
        digits_len = 3
    else:
        # Very short combined words, use 4 digits for length
        digits_len = 4

    num_block = random_digits(digits_len)
    password = base + num_block

    # Ensure it is at least 9 chars
    if len(password) < 9:
        password += random_digits(9 - len(password))

    # Hard cap at 15 chars
    if len(password) > 15:
        password = password[:15]

    # Ensure '=' is never the first character
    if password.startswith("="):
        replacement = secure_choice(string.ascii_letters + string.digits)
        password = replacement + password[1:]

    # Guarantee at least one uppercase in low-security mode
    if low_security:
        password = ensure_uppercase(password)

    return password


# ---------------- High security mode (long, high entropy) ---------------- #

def generate_password_high_security(word_list, low_security: bool = False):
    """
    Generate a high-entropy password with 3–4 words, random casing,
    symbol injection, and a 3–4 digit number block.
    Length is not restricted here, so results are longer.
    """
    # No backtick; '=' allowed but we will block it as first char later
    SYMBOLS = "!@#$%^&*+=?-_."

    # 3 or 4 words
    num_words = 3 if secrets.randbits(1) else 4

    words = [
        generate_random_word(word_list, low_security=low_security)
        for _ in range(num_words)
    ]

    # Remove spaces in each word
    words = [w.replace(" ", "") for w in words]

    # Maybe inject symbols into one or more words
    for i in range(len(words)):
        if secrets.randbits(1):
            words[i] = maybe_inject_symbol(words[i], SYMBOLS)

    # Shuffle words
    rng = secrets.SystemRandom()
    rng.shuffle(words)

    # Number block 3–4 digits
    if secrets.randbits(1):
        num_block = random_digits(3)
    else:
        num_block = random_digits(4)

    sym_block = secure_choice(SYMBOLS)

    # Combine using patterns
    patterns = [
        "{w}{w2}{num}{sym}",
        "{num}{w}{sym}{w2}",
        "{w}{sym}{w2}{num}",
        "{sym}{w}{num}{w2}",
    ]

    if len(words) == 1:
        w = words[0]
        w2 = ""
    else:
        w = words[0]
        w2 = ''.join(words[1:])

    pattern = secure_choice(patterns)
    password = pattern.format(w=w, w2=w2, num=num_block, sym=sym_block)

    # Ensure '=' is never the first character
    if password.startswith("="):
        replacement = secure_choice(string.ascii_letters + string.digits)
        password = replacement + password[1:]

    # Guarantee at least one uppercase in low-security mode
    if low_security:
        password = ensure_uppercase(password)

    return password


# ---------------- Wrapper ---------------- #

def generate_password(word_list, security_level: str = "standard"):
    """
    security_level: "low", "standard", or "high"
    """
    if security_level == "high":
        # High security ignores low/standard distinction and just goes full strength
        return generate_password_high_security(word_list, low_security=False)
    elif security_level == "low":
        # Same length controls as standard, but reduced capitalization
        return generate_password_standard(word_list, low_security=True)
    else:
        # Standard balanced mode
        return generate_password_standard(word_list, low_security=False)


# ---------------- GUI wiring ---------------- #

def generate_passwords():
    try:
        num_passwords = int(num_passwords_entry.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number.")
        return

    try:
        word_list = read_encrypted_word_list('encrypted_words.csv', 'key.key')
    except FileNotFoundError:
        messagebox.showerror(
            "Missing Files",
            "Could not find 'encrypted_words.csv' or 'key.key'.\n"
            "Make sure they are in the same folder as this program."
        )
        return
    except Exception as e:
        messagebox.showerror("Error", f"Error reading encrypted word list:\n{e}")
        return

    level = security_level_var.get()  # "low", "standard", or "high"

    passwords = [
        generate_password(word_list, security_level=level)
        for _ in range(num_passwords)
    ]

    # Show up to 10 in the UI, otherwise save to file
    if num_passwords <= 10:
        passwords_textbox.config(state=tk.NORMAL)
        passwords_textbox.delete(1.0, tk.END)
        for password in passwords:
            passwords_textbox.insert(tk.END, password + '\n')
        passwords_textbox.config(state=tk.DISABLED)
    else:
        output_file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        if output_file:
            try:
                with open(output_file, 'w') as file:
                    for password in passwords:
                        file.write(password + '\n')
                messagebox.showinfo(
                    "Success",
                    f"{num_passwords} passwords generated and saved to {output_file}"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file:\n{e}")


# ---------------- Tkinter UI setup ---------------- #

app = tk.Tk()
app.title("Password Generator")

# Resolve icon path so it works both as script and as frozen EXE
if getattr(sys, 'frozen', False):
    base_dir = os.path.dirname(sys.executable)
else:
    base_dir = os.path.dirname(__file__)

icon_path = os.path.join(base_dir, "password_generator.ico")

try:
    app.iconbitmap(icon_path)
except Exception:
    pass


tk.Label(app, text="Number of Passwords:").pack(pady=5)
num_passwords_entry = tk.Entry(app)
num_passwords_entry.pack(pady=5)
num_passwords_entry.insert(0, "1")  # Set default value to 1

# Security level selector (radio buttons)
security_level_var = tk.StringVar(value="standard")

tk.Label(app, text="Security level:").pack(pady=(10, 0))

tk.Radiobutton(
    app,
    text="Low (reduced capitalization)",
    variable=security_level_var,
    value="low"
).pack(anchor="w", padx=30)

tk.Radiobutton(
    app,
    text="Standard (balanced)",
    variable=security_level_var,
    value="standard"
).pack(anchor="w", padx=30)

tk.Radiobutton(
    app,
    text="High (long multi-word)",
    variable=security_level_var,
    value="high"
).pack(anchor="w", padx=30)

tk.Button(app, text="Generate Passwords", command=generate_passwords).pack(pady=20)

passwords_textbox = tk.Text(
    app,
    height=10,
    width=50,
    state=tk.DISABLED,
    font=("Consolas", 10)
)
passwords_textbox.pack(pady=5)


