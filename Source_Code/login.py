import getpass
import os
import bcrypt
from add_password import *
from viewing import *
from update import *
from delete import *

USERS_FILE = "Storage_File/users.txt"

# -----------------------------
# LOGIN FUNCTION
# -----------------------------
def login():
    try:
        if not os.path.exists(USERS_FILE):
            print(f"{RED}No users found. Please register first.{RESET}")
            return None

        username_attempts = 3
        user_record = None

        while username_attempts > 0:
            try:
                username_input = input("===> Enter username: ").strip()
            except Exception:
                print(f"{RED}Input error occurred.{RESET}")
                username_attempts -= 1
                continue

            try:
                with open(USERS_FILE, "r") as file:
                    for line in file:
                        parts = line.strip().split(":")
                        if len(parts) < 6:
                            continue

                        user_id, username, hashed_password, hashed_color, hashed_pet, hashed_zodiac = parts

                        if username_input.lower() == username.lower():
                            user_record = {
                                "user_id": user_id,
                                "username": username,
                                "hashed_password": hashed_password,
                                "hashed_color": hashed_color,
                                "hashed_pet": hashed_pet,
                                "hashed_zodiac": hashed_zodiac
                            }
                            break
            except FileNotFoundError:
                print(f"{RED}User file not found.{RESET}")
                return None
            except PermissionError:
                print(f"{RED}Permission denied while reading users file.{RESET}")
                return None
            except Exception:
                print(f"{RED}Error reading users file.{RESET}")
                return None

            if user_record:
                break
            else:
                username_attempts -= 1
                print(f"{RED} Username not found! Attempts left: {username_attempts}\n{RESET}")

        if not user_record:
            print(f"{RED}Maximum username attempts reached. Exiting login.{RESET}")
            return None

        password_attempts = 3
        while password_attempts > 0:
            try:
                password_input = getpass.getpass("===> Enter password: ").strip()
            except Exception:
                print(f"{RED}Password input error.{RESET}")
                password_attempts -= 1
                continue

            try:
                if bcrypt.checkpw(
                    password_input.encode(),
                    user_record["hashed_password"].encode()
                ):
                    os.system("cls")
                    print(f"\n{GREEN}Login successful! Welcome, {user_record['username']}.{RESET}")
                    login_menu(user_record)
                    return user_record
            except ValueError:
                print(f"{RED}Password verification failed.{RESET}")
                return None
            except Exception:
                print(f"{RED}Authentication error occurred.{RESET}")
                return None

            password_attempts -= 1
            print(f"{RED}Incorrect password! Attempts left: {password_attempts}\n{RESET}")

        print(f"{RED}Maximum password attempts reached. Exiting login.{RESET}")
        return None

    except KeyboardInterrupt:
        print(f"\n{RED}Login cancelled by user.{RESET}")
        return None
    except Exception:
        print(f"{RED}Unexpected error occurred during login.{RESET}")
        return None

# -----------------------------
# LOGIN MENU
# -----------------------------
def login_menu(user_data):
    try:
        # Display menu after user successfully logs in
        while True:
            print("\n=== Options Menu ===")
            print("1. Add Password")
            print("2. Normal View")
            print("3. Special View")
            print("4. Update Password")
            print("5. Delete Password")
            print("0. Logout")

            try:
                choice = input("Select an option (1-4): ").strip()
            except Exception:
                print(f"{RED}Input error. Try again.{RESET}")
                continue

            if choice == "1":
                add_password(user_data)
            elif choice == "2":
                normal_view(user_data)
            elif choice == "3":
                special_view(user_data)
            elif choice == "4":
                update_password(user_data)
            elif choice == "5":
                delete_password(user_data)
            elif choice == "0":
                try:
                    os.system("cls")
                except Exception:
                    pass
                print(f"{BLUE}={RESET}" * 200 + "\n")
                print("Logging out ...\n")
                print(f"{BLUE}={RESET}" * 200 + "\n")
                break
            else:
                print(f"{RED}Invalid choice. Try again.{RESET}")

    except KeyboardInterrupt:
        print(f"\n{RED}Logout interrupted by user.{RESET}")
    except Exception:
        print(f"{RED}Unexpected error occurred in login menu.{RESET}")
