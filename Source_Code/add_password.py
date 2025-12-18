import os
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode
from base64 import b64decode
from register import *

PASSWORD_FILE = "Storage_File/password_storage.txt"

# -----------------------------
# AES ENCRYPT FUNCTION
# -----------------------------
def encrypt_aes(plain_text, key_bytes):
    try:
        cipher = AES.new(key_bytes, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
        return b64encode(cipher.nonce + tag + ciphertext).decode()
        # FORMAT STORED: nonce(16) + tag(16) + ciphertext
    except Exception:
        print(f"{RED}Encryption error occurred.{RESET}")
        return ""

# -----------------------------
# AES DECRYPT FUNCTION
# -----------------------------
def decrypt_aes(enc_text, key_bytes):
    try:
        data = b64decode(enc_text)
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        raise Exception("AES decryption failed") from e
    
# -----------------------------
# ADD PASSWORD FUNCTION
# -----------------------------
def add_password(user_data):
    try:
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

            # Option 1: Auto-generate 32-byte key
            if choice == "1":
                try:
                    key_bytes = get_random_bytes(32)
                    key = key_bytes.hex()
                    print(f"{BLUE}Generated AES key (save it!): {key}{RESET}")
                    break
                except Exception:
                    print(f"{RED}Error generating AES key.{RESET}")
                    return

            # Option 2: User enters their own key
            elif choice == "2":
                for attempt in range(3):
                    key = masked_input("===> Enter AES key (your own key): ").strip()
                    if key:
                        try:
                            key_bytes = key.ljust(32)[:32].encode()
                            break
                        except Exception:
                            print(f"{RED}Invalid AES key format.{RESET}")
                            continue
                    print(f"{RED}Key cannot be empty. Attempts left: {2 - attempt}{RESET}")
                else:
                    print(f"{RED}Maximum AES key attempts reached. Exiting.{RESET}")
                    return
                break

            else:
                print(f"{RED}Invalid option. Enter 1 or 2.{RESET}")

        # Save encrypted password and description
        save_password(user_data["user_id"], password, description, extra_key=key_bytes)

    except KeyboardInterrupt:
        print(f"\n{RED}Operation cancelled by user.{RESET}")
    except Exception:
        print(f"{RED}Unexpected error occurred while adding password.{RESET}")

# -----------------------------
# SAVE PASSWORD FUNCTION
# -----------------------------
def save_password(user_id, plain_password, description, extra_key):
    try:
        # Encrypt password using user's AES key
        stored_password = encrypt_aes(plain_password, extra_key)
        if not stored_password:
            return

        # Encrypt description using fixed key "Description"
        desc_key_bytes = "Description".ljust(32)[:32].encode()
        stored_description = encrypt_aes(description, desc_key_bytes)
        if not stored_description:
            return

        new_entry = f"{stored_password}:{stored_description}"

        # Ensure file exists
        os.makedirs(os.path.dirname(PASSWORD_FILE), exist_ok=True)
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

    except PermissionError:
        print(f"{RED}Permission denied while saving password.{RESET}")
    except FileNotFoundError:
        print(f"{RED}Password file not found.{RESET}")
    except Exception:
        print(f"{RED}Unexpected error occurred while saving password.{RESET}")
