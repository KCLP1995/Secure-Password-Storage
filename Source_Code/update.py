from viewing import *
import os
import getpass

def update_password(user_data):
    try:
        user_id = user_data["user_id"]

        # --------------------------
        # TWO-STEP VERIFICATION
        # --------------------------
        try:
            if not two_step_verification(user_data):
                return
        except Exception:
            print(f"{RED}Two-step verification error.{RESET}")
            return

        # Fixed key for description
        desc_key_bytes = "Description".ljust(32)[:32].encode()
        password_entries = []
        found = False

        # --------------------------
        # READ PASSWORD FILE
        # --------------------------
        try:
            with open(PASSWORD_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith(f"{user_id}:"):
                        continue

                    found = True
                    items = line.split(":", 1)[1].split("|")

                    for item in items:
                        try:
                            enc_pwd, enc_desc = item.split(":")
                        except ValueError:
                            continue

                        try:
                            description = decrypt_aes(enc_desc, desc_key_bytes)
                        except Exception:
                            description = "[Cannot decrypt description]"

                        masked = enc_pwd[0] + "*" * (len(enc_pwd) - 1)
                        password_entries.append({
                            "enc_pwd": enc_pwd,
                            "description": description,
                            "masked_pwd": masked
                        })
        except FileNotFoundError:
            print(f"{RED}Password file not found.{RESET}")
            return
        except PermissionError:
            print(f"{RED}Permission denied while reading password file.{RESET}")
            return
        except Exception:
            print(f"{RED}Error reading password file.{RESET}")
            return

        if not found:
            print(f"{RED}No passwords found for this user.{RESET}")
            return

        # --------------------------
        # DISPLAY PASSWORDS
        # --------------------------
        try:
            os.system("cls")
        except Exception:
            pass

        print(f"\n{BLUE}=== Your Stored Passwords ==={RESET}")

        for idx, entry in enumerate(password_entries, start=1):
            print(f"\n{GREEN}Password {idx}:{RESET}")
            print(f"  Description: {entry['description']}")
            print(f"  Password: {entry['masked_pwd']}")

        # --------------------------
        # SELECT PASSWORD TO UPDATE
        # --------------------------
        while True:
            try:
                choice = input("\nEnter number of password to update (or 'q' to quit): ").strip()
            except Exception:
                print(f"{RED}Input error. Try again.{RESET}")
                continue

            if choice.lower() == "q":
                return

            if not choice.isdigit() or not (1 <= int(choice) <= len(password_entries)):
                print(f"{RED}Invalid choice. Try again.{RESET}")
                continue

            index = int(choice) - 1
            selected = password_entries[index]
            break

        # --------------------------
        # ASK IF USER WANTS TO CHANGE AES KEY
        # --------------------------
        print("\nDo you want to update the AES key for this password?")
        try:
            option = input(
                f"Enter {BLUE}'y'{RESET} for new key, {BLUE}'n'{RESET} to keep current key: "
            ).strip().lower()
        except Exception:
            print(f"{RED}Input error.{RESET}")
            return

        # --------------------------
        # VERIFY CURRENT AES KEY
        # --------------------------
        for attempt in range(3):
            try:
                current_key = getpass.getpass("Enter CURRENT AES key: ").strip()

                if all(c in "0123456789abcdefABCDEF" for c in current_key) and len(current_key) == 64:
                    key_bytes = bytes.fromhex(current_key)
                else:
                    key_bytes = current_key.ljust(32)[:32].encode()

                current_password = decrypt_aes(selected["enc_pwd"], key_bytes)
                break
            except Exception:
                print(f"{RED}Wrong AES key. Attempts left: {2 - attempt}{RESET}")
                continue
        else:
            print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
            return

        # --------------------------
        # NEW AES KEY (OPTIONAL)
        # --------------------------
        encrypt_key_bytes = key_bytes
        if option == "y":
            for attempt in range(3):
                try:
                    new_key = getpass.getpass("Enter NEW AES key: ").strip()
                except Exception:
                    print(f"{RED}Input error.{RESET}")
                    continue

                if not new_key:
                    print(f"{RED}Key cannot be empty. Attempts left: {2 - attempt}{RESET}")
                    continue

                encrypt_key_bytes = new_key.ljust(32)[:32].encode()
                break
            else:
                print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
                return

        # --------------------------
        # NEW PASSWORD
        # --------------------------
        for attempt in range(3):
            print(f"\n{YELLOW}must be more than 8 characters(uppercase, lowercase, number, and special character){RESET}")
            try:
                new_pwd = getpass.getpass("===> Enter NEW password: ").strip()
            except Exception:
                print(f"{RED}Input error.{RESET}")
                continue

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
        try:
            new_desc = masked_input(
                "===> Enter new description (leave blank to keep current): "
            ).strip() or selected["description"]
        except Exception:
            new_desc = selected["description"]

        # --------------------------
        # ENCRYPT NEW VALUES
        # --------------------------
        try:
            new_enc_pwd = encrypt_aes(new_pwd, encrypt_key_bytes)
            new_enc_desc = encrypt_aes(new_desc, desc_key_bytes)
        except Exception:
            print(f"{RED}Encryption error.{RESET}")
            return

        password_entries[index] = {
            "enc_pwd": new_enc_pwd,
            "description": new_desc,
            "masked_pwd": new_enc_pwd[0] + "*" * (len(new_enc_pwd) - 1)
        }

        # --------------------------
        # SAVE UPDATED FILE
        # --------------------------
        new_lines = []
        try:
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
        except Exception:
            print(f"{RED}Error saving updated password file.{RESET}")
            return

        # --------------------------
        # FINISH
        # --------------------------
        if option == "y":
            print(f"{GREEN}Password, description, and AES key updated successfully !!!{RESET}")
            try:
                input("Press Any Key to Continue")
            except Exception:
                pass
        else:
            print(f"{GREEN}Password and description updated successfully !!!{RESET}")
            try:
                input("Press Any Key to Continue")
            except Exception:
                pass

    except KeyboardInterrupt:
        print(f"\n{RED}Operation cancelled by user.{RESET}")
    except Exception:
        print(f"{RED}Unexpected error occurred during password update.{RESET}")
