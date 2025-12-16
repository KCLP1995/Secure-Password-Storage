import os
import getpass
from register import *
from add_password import *
from Crypto.Cipher import AES
from base64 import b64decode
import bcrypt

# -----------------------------
# NORMAL VIEW (Only masked encrypted)
# -----------------------------
def normal_view(user_data):
    user_id = user_data["user_id"]

    if not os.path.exists(PASSWORD_FILE):
        print(f"{RED}No passwords stored yet.{RESET}")
        return

    found = False

    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith(f"{user_id}:"):
                continue

            found = True
            entries = line.split(":", 1)[1]
            item_list = entries.split("|")

            os.system("cls")
            print(f"\n{BLUE}=== Your Stored Passwords (Encrypted Preview) ==={RESET}")

            count = 1
            for item in item_list:
                enc_pwd, enc_desc = item.split(":")

                masked_pwd = enc_pwd[0] + "*" * (len(enc_pwd)-1)
                masked_desc = enc_desc[0] + "*" * (len(enc_desc)-1)

                print(f"\n{BLUE}Password {count}:{RESET}")
                print(f"  Encrypted Description: {masked_desc}")
                print(f"  Encrypted Password: {masked_pwd}")
                count += 1
            print("\n")
            input("Press Any Key To Continue")
            os.system("cls")

    if not found:
        print(f"{RED}No passwords found for this user.{RESET}")

# -----------------------------
# TWO-STEP VERIFICATION FUNCTION
# -----------------------------
def two_step_verification(user_data, max_attempts=3):
    attempts = max_attempts
    while attempts > 0:
        print(f"\n{YELLOW}== Two-Step Verification Required =={RESET}")
        color_input = masked_input("Enter your favorite color: ").strip()
        pet_input = masked_input("Enter your favorite pet: ").strip()
        zodiac_input = masked_input("Enter your zodiac sign: ").strip()

        if (
            bcrypt.checkpw(color_input.encode(), user_data["hashed_color"].encode()) and
            bcrypt.checkpw(pet_input.encode(), user_data["hashed_pet"].encode()) and
            bcrypt.checkpw(zodiac_input.encode(), user_data["hashed_zodiac"].encode())
        ):
            print(f"{GREEN}Verification successful!{RESET}")
            return True

        attempts -= 1
        print(f"{RED}Incorrect information! Attempts left: {attempts}{RESET}")

    print(f"{RED}Maximum verification attempts reached. Access denied.{RESET}")
    return False

# -----------------------------
# AES DECRYPT FUNCTION
# -----------------------------
def decrypt_aes(enc_text, key_bytes):
    data = b64decode(enc_text)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# -----------------------------
# SPECIAL VIEW (Dynamic password decryption)
# -----------------------------
def special_view(user_data):
    user_id = user_data["user_id"]

    if not os.path.exists(PASSWORD_FILE):
        print(f"{RED}No stored passwords found.{RESET}")
        return

    # --------------------------
    # TWO-STEP VERIFICATION
    # --------------------------
    verified = two_step_verification(user_data)
    if not verified:
        return

    # Fixed key for description
    desc_key_bytes = "Description".ljust(32)[:32].encode()
    password_entries = []
    found = False

    # Read user's password entries
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith(f"{user_id}:"):
                continue

            found = True
            entries = line.split(":", 1)[1]
            item_list = entries.split("|")

            for item in item_list:
                enc_pwd, enc_desc = item.split(":")
                try:
                    description = decrypt_aes(enc_desc, desc_key_bytes)
                except Exception:
                    description = "[Cannot decrypt description]"

                masked_pwd = enc_pwd[0] + "*" * (len(enc_pwd) - 1)
                password_entries.append({
                    "enc_pwd": enc_pwd,
                    "description": description,
                    "masked_pwd": masked_pwd
                })

    if not found:
        print(f"{RED}No passwords found for this user.{RESET}")
        return

    # Display all passwords (masked) with decrypted description
    os.system("cls")
    print(f"\n{BLUE}=== Your Stored Passwords ==={RESET}")
    for idx, entry in enumerate(password_entries, start=1):
        print(f"\n{GREEN}Password {idx}:{RESET}")
        print(f"  Description: {entry['description']}")
        print(f"  Password: {entry['masked_pwd']}")

    # --------------------------
    # Dynamic decryption per user choice
    # --------------------------
    while True:
        choice = input(f"\nEnter number of password to decrypt (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            os.system("cls")
            break

        if not choice.isdigit() or not (1 <= int(choice) <= len(password_entries)):
            print(f"{RED}Invalid choice. Try again.{RESET}")
            continue

        index = int(choice) - 1
        selected_entry = password_entries[index]

        # Ask for AES key
        key_input = getpass.getpass(f"Enter AES key for Password {choice}: ").strip()

        # Convert hex to bytes if user entered a generated key
        try:
            key_bytes = bytes.fromhex(key_input)
        except ValueError:
            # If not hex, use user string key
            key_bytes = key_input.ljust(32)[:32].encode()

        try:
            full_password = decrypt_aes(selected_entry["enc_pwd"], key_bytes)
            print(f"\n{GREEN}Decrypted Password {choice}:{RESET} {full_password}")
        except Exception:
            print(f"{RED}Wrong AES key! Cannot decrypt this password.{RESET}")
