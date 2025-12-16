from register import *
from viewing import *
import os
import time

def delete_password(user_data):
    user_id = user_data["user_id"]

    # --------------------------
    # TWO-STEP VERIFICATION
    # --------------------------
    if not two_step_verification(user_data):
        return

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

                masked_pwd = enc_pwd[0] + "*" * (len(enc_pwd) - 1)

                password_entries.append({
                    "enc_pwd": enc_pwd,
                    "description": description,
                    "masked_pwd": masked_pwd
                })

    if not found or len(password_entries) == 0:
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
        
        confirm = input(f"Type {BLUE}'y'{RESET} to confirm or {BLUE}'n'{RESET} to cancel: ").strip().lower()
        
        if confirm == "y":
            break  # proceed with deletion
        elif confirm == "n":
            print(f"{RED}Deletion cancelled.{RESET}")
            time.sleep(1)
            os.system("cls")
            return
        else:
            print(f"{RED}Invalid input. Please type 'yes' or 'no'. Attempts left: {2 - attempt}{RESET}")
    else:
        print(f"{RED}Maximum attempts reached. Deletion cancelled.{RESET}")
        os.system("cls")
        return


    # --------------------------
    # DELETE ENTRY
    # --------------------------
    del password_entries[index]

    # --------------------------
    # SAVE UPDATED LIST
    # --------------------------
    new_lines = []
    with open(PASSWORD_FILE, "r") as f:
        for line in f:
            if line.startswith(f"{user_id}:"):
                if len(password_entries) == 0:
                    # user now has no passwords → remove line
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

    print(f"{GREEN}Password deleted successfully!{RESET}")
    input("Press Any Key To Continue")
    os.system("cls")
