from viewing import *
import os
import getpass

def update_password(user_data):
    user_id = user_data["user_id"]

    # --------------------------
    # TWO-STEP VERIFICATION
    # --------------------------
    if not two_step_verification(user_data):
        return

    # Fixed key for description
    desc_key_bytes = "Description".ljust(32)[:32].encode()
    password_entries = []
    found = False

    # --------------------------
    # READ PASSWORD FILE
    # --------------------------
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith(f"{user_id}:"):
                continue

            found = True
            items = line.split(":", 1)[1].split("|")

            for item in items:
                enc_pwd, enc_desc = item.split(":")

                try:
                    description = decrypt_aes(enc_desc, desc_key_bytes)
                except:
                    description = "[Cannot decrypt description]"

                masked = enc_pwd[0] + "*" * (len(enc_pwd) - 1)
                password_entries.append({
                    "enc_pwd": enc_pwd,
                    "description": description,
                    "masked_pwd": masked
                })

    if not found:
        print(f"{RED}No passwords found for this user.{RESET}")
        return

    # --------------------------
    # DISPLAY PASSWORDS
    # --------------------------
    os.system("cls")
    print(f"\n{BLUE}=== Your Stored Passwords ==={RESET}")

    for idx, entry in enumerate(password_entries, start=1):
        print(f"\n{GREEN}Password {idx}:{RESET}")
        print(f"  Description: {entry['description']}")
        print(f"  Password: {entry['masked_pwd']}")

    # --------------------------
    # SELECT PASSWORD TO UPDATE
    # --------------------------
    while True:
        choice = input("\nEnter number of password to update (or 'q' to quit): ").strip()
        if choice.lower() == "q":
            return

        if not choice.isdigit() or not (1 <= int(choice) <= len(password_entries)):
            print(f"{RED}Invalid choice. Try again.{RESET}")
            continue

        index = int(choice) - 1
        selected = password_entries[index]
        break

    # --------------------------
    # ASK IF USER WANTS TO CHANGE AES KEY (y/n)
    # --------------------------
    print("\nDo you want to update the AES key for this password?")
    option = input(f"Enter {BLUE}'y'{RESET} for new key, {BLUE}'n'{RESET} to keep current key: ").strip().lower()

    # --------------------------
    # VERIFY CURRENT AES KEY (required)
    # --------------------------
    for attempt in range(3):
        current_key = getpass.getpass("Enter CURRENT AES key: ").strip()
        
        try:
            # Convert hex string back to bytes if it was generated
            if all(c in "0123456789abcdefABCDEF" for c in current_key) and len(current_key) == 64:
                key_bytes = bytes.fromhex(current_key)
            else:
                # User-entered key (normal string), pad/truncate to 32 bytes
                key_bytes = current_key.ljust(32)[:32].encode()
            
            # Try decrypting with provided current key
            current_password = decrypt_aes(selected["enc_pwd"], key_bytes)
            break
        except Exception:
            print(f"{RED}Wrong AES key. Attempts left: {2 - attempt}{RESET}")
            continue
    else:
        print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
        return


    # --------------------------
    # IF USER WANTS A NEW AES KEY, ASK FOR IT (non-empty)
    # --------------------------
    encrypt_key_bytes = key_bytes  # default: keep using current key to encrypt new pwd
    if option == "y":
        for attempt in range(3):
            new_key = getpass.getpass("Enter NEW AES key: ").strip()
            if not new_key:
                print(f"{RED}Key cannot be empty. Attempts left: {2 - attempt}{RESET}")
                continue
            # set new key bytes to be used to encrypt the updated password
            encrypt_key_bytes = new_key.ljust(32)[:32].encode()
            break
        else:
            print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
            return

    # --------------------------
    # NEW PASSWORD (NOT EMPTY)
    # --------------------------
    for attempt in range(3):
        print(f"\n{YELLOW}must be more than 8 characters(uppercase, lowercase, number, and special character){RESET}")
        new_pwd = getpass.getpass("===> Enter NEW password: ").strip()

        if not new_pwd:
            print(f"{RED}Password cannot be empty. Attempts left: {2 - attempt}{RESET}")
            continue

        if validate_password(new_pwd):
            break

        print(f"{RED}Invalid password. Attempts left: {2 - attempt}{RESET}")

    else:
        print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
        return

    # --------------------------
    # NEW DESCRIPTION
    # --------------------------
    new_desc = masked_input("===> Enter new description (leave blank to keep current): ").strip() or selected["description"]

    # --------------------------
    # ENCRYPT NEW VALUES
    # --------------------------
    # Encrypt password with encrypt_key_bytes (either new key or current key)
    new_enc_pwd = encrypt_aes(new_pwd, encrypt_key_bytes)
    # Description still uses fixed desc_key_bytes
    new_enc_desc = encrypt_aes(new_desc, desc_key_bytes)

    password_entries[index] = {
        "enc_pwd": new_enc_pwd,
        "description": new_desc,
        "masked_pwd": new_enc_pwd[0] + "*" * (len(new_enc_pwd) - 1)
    }

    # --------------------------
    # SAVE UPDATED FILE
    # --------------------------
    new_lines = []
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            if line.startswith(f"{user_id}:"):
                combined = "|".join([
                    f"{e['enc_pwd']}:{encrypt_aes(e['description'], desc_key_bytes)}"
                    for e in password_entries
                ])
                new_lines.append(f"{user_id}:{combined}\n")
            else:
                new_lines.append(line)

    with open(PASSWORD_FILE, "w") as f:
        f.writelines(new_lines)

    # --------------------------
    # FINISH
    # --------------------------
    if option == "y":
        print(f"{GREEN}Password, description, and AES key updated successfully !!!{RESET}")
        os.system("cls")
    else:
        print(f"{GREEN}Password and description updated successfully !!!{RESET}")
        os.system("cls")
