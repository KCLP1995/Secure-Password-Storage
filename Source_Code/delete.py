from register import *
from viewing import *
import os
import time

def delete_password(user_data):
    try:
        user_id = user_data["user_id"]

        # --------------------------
        # TWO-STEP VERIFICATION
        # --------------------------
        try:
            if not two_step_verification(user_data):
                return
        except Exception:
            print(f"{RED}Two-step verification failed due to an error.{RESET}")
            return

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

                        masked_pwd = enc_pwd[0] + "*" * (len(enc_pwd) - 1)

                        password_entries.append({
                            "enc_pwd": enc_pwd,
                            "description": description,
                            "masked_pwd": masked_pwd
                        })
        except FileNotFoundError:
            print(f"{RED}Password storage file not found.{RESET}")
            return
        except PermissionError:
            print(f"{RED}Permission denied while reading password file.{RESET}")
            return
        except Exception:
            print(f"{RED}Error reading password file.{RESET}")
            return

        if not found or len(password_entries) == 0:
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
        # SELECT PASSWORD TO DELETE
        # --------------------------
        while True:
            choice = input("\nEnter number of password to DELETE (or 'q' to quit): ").strip()
            if choice.lower() == "q":
                return

            if not choice.isdigit() or not (1 <= int(choice) <= len(password_entries)):
                print(f"{RED}Invalid choice. Try again.{RESET}")
                continue

            index = int(choice) - 1
            selected = password_entries[index]
            break

        # --------------------------
        # CONFIRM DELETION (strict yes/no)
        # --------------------------
        for attempt in range(3):
            print(f"\n{YELLOW}Are you sure you want to delete this password?{RESET}")
            print(f"Description: {selected['description']}")
            print(f"Masked Password: {selected['masked_pwd']}")
            
            confirm = input(
                f"Type {BLUE}'y'{RESET} to confirm or {BLUE}'n'{RESET} to cancel: "
            ).strip().lower()
            
            if confirm == "y":
                break
            elif confirm == "n":
                print(f"{RED}Deletion cancelled.{RESET}")
                time.sleep(1)
                try:
                    os.system("cls")
                except Exception:
                    pass
                return
            else:
                print(
                    f"{RED}Invalid input. Please type 'yes' or 'no'. "
                    f"Attempts left: {2 - attempt}{RESET}"
                )
        else:
            print(f"{RED}Maximum attempts reached. Deletion cancelled.{RESET}")
            try:
                os.system("cls")
            except Exception:
                pass
            return

        # --------------------------
        # DELETE ENTRY
        # --------------------------
        try:
            del password_entries[index]
        except Exception:
            print(f"{RED}Error deleting selected password.{RESET}")
            return

        # --------------------------
        # SAVE UPDATED LIST
        # --------------------------
        new_lines = []
        try:
            with open(PASSWORD_FILE, "r") as f:
                for line in f:
                    if line.startswith(f"{user_id}:"):
                        if len(password_entries) == 0:
                            continue

                        combined = "|".join([
                            f"{e['enc_pwd']}:{encrypt_aes(e['description'], desc_key_bytes)}"
                            for e in password_entries
                        ])

                        new_lines.append(f"{user_id}:{combined}\n")
                    else:
                        new_lines.append(line)

            with open(PASSWORD_FILE, "w") as f:
                f.writelines(new_lines)

        except PermissionError:
            print(f"{RED}Permission denied while saving password file.{RESET}")
            return
        except Exception:
            print(f"{RED}Error saving updated password list.{RESET}")
            return

        print(f"{GREEN}Password deleted successfully!{RESET}")
        input("Press Any Key To Continue")
        try:
            os.system("cls")
        except Exception:
            pass

    except KeyboardInterrupt:
        print(f"\n{RED}Operation cancelled by user.{RESET}")
    except Exception:
        print(f"{RED}Unexpected error occurred during password deletion.{RESET}")
