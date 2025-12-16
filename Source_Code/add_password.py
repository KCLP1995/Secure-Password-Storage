import os
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
from register import *

PASSWORD_FILE = "Storage_File/password_storage.txt"

# -----------------------------
# AES ENCRYPT FUNCTION
# -----------------------------
def encrypt_aes(plain_text, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    return b64encode(cipher.nonce + tag + ciphertext).decode()
    # FORMAT STORED: nonce(16) + tag(16) + ciphertext

# -----------------------------
# ADD PASSWORD FUNCTION
# -----------------------------
def add_password(user_data):
    print(f"\n{YELLOW}Password must include uppercase, lowercase, number, and special character{RESET}")

    # Password validation
    for attempt in range(3):
        pwd = getpass.getpass("===> Enter password to store: ").strip()
        if pwd and validate_password(pwd):
            password = pwd
            break
        print(f"{RED}Invalid password! Attempts left: {2 - attempt}{RESET}")
    else:
        print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
        return

    description = masked_input("===> Enter description (optional): ").strip() or "No description"

    # AES key selection
    while True:
        print("\nAES Key Options:")
        print("1. Generate new key")
        print("2. Input your own key")
        choice = input("Select option (1-2): ").strip()

        # Option 1: Auto-generate 32‑byte key
        if choice == "1":
            key_bytes = get_random_bytes(32)
            key = key_bytes.hex()  # show as hex string to user
            print(f"{BLUE}Generated AES key (save it!): {key}{RESET}")
            break

        # Option 2: User enters their own key
        elif choice == "2":
            for attempt in range(3):
                key = masked_input("===> Enter AES key (your own key): ").strip()
                if key:
                    key_bytes = key.ljust(32)[:32].encode()
                    break
                print(f"{RED}Key cannot be empty. Attempts left: {2 - attempt}{RESET}")
            else:
                print(f"{RED}Maximum AES key attempts reached. Exiting.{RESET}")
                return
            break

        else:
            print(f"{RED}Invalid option. Enter 1 or 2.{RESET}")

    # Save encrypted password and description
    save_password(user_data["user_id"], password, description, extra_key=key_bytes)


# -----------------------------
# SAVE PASSWORD FUNCTION
# -----------------------------
def save_password(user_id, plain_password, description, extra_key):
    # Encrypt password using user's AES key
    stored_password = encrypt_aes(plain_password, extra_key)
    
    # Encrypt description using fixed key "Description"
    desc_key_bytes = "Description".ljust(32)[:32].encode()
    stored_description = encrypt_aes(description, desc_key_bytes)

    new_entry = f"{stored_password}:{stored_description}"

    # Ensure file exists
    if not os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "w") as f:
            pass

    # Load current file
    with open(PASSWORD_FILE, "r") as f:
        lines = f.readlines()

    updated = False
    new_lines = []

    # Update existing user entry
    for line in lines:
        line = line.strip()
        if line.startswith(f"{user_id}:"):
            new_line = line + "|" + new_entry
            new_lines.append(new_line + "\n")
            updated = True
        else:
            new_lines.append(line + "\n")

    # Create new user entry if not exist
    if not updated:
        new_lines.append(f"{user_id}:{new_entry}\n")

    # Write back to file
    with open(PASSWORD_FILE, "w") as f:
        f.writelines(new_lines)

    print(f"{GREEN}Password added successfully!{RESET}")
    input("Press any key to continue...")
    os.system("cls")
