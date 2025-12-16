import re
import os
import getpass
import bcrypt

# -----------------------------
# WINDOWS-ONLY INPUT HANDLING
# -----------------------------
try:
    import msvcrt
except ImportError:
    print("Error: This program must be run on Windows.")
    exit()

# -----------------------------
# Color
# -----------------------------
RED = '\033[91m'
YELLOW = '\033[33m'
BLUE = '\033[94m'
RESET = '\033[0m'
GREEN = '\033[92m'

# -----------------------------
# MASKED INPUT (FIRST LETTER VISIBLE)
# -----------------------------
def masked_input(prompt):
    try:
        print(prompt, end='', flush=True)
        result = ''
        while True:
            ch = msvcrt.getwch()
            if ch in ('\r', '\n'):
                print()
                break
            elif ch == '\x08':
                if len(result) > 0:
                    result = result[:-1]
                    print('\b \b', end='', flush=True)
            else:
                result += ch
                if len(result) == 1:
                    print(ch, end='', flush=True)
                else:
                    print('*', end='', flush=True)
        return result.strip()
    except Exception:
        print(f"{RED}Input error occurred.{RESET}")
        return ""

# -----------------------------
# VALIDATION FUNCTIONS
# -----------------------------
def validate_username(username):
    try:
        pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)[A-Za-z0-9]{4,8}$"
        return bool(re.match(pattern, username))
    except Exception:
        return False

def validate_password(password):
    try:
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$"
        return bool(re.match(pattern, password))
    except Exception:
        return False

def validate_pet_color(petColor):
    try:
        return petColor and petColor[0].isupper()
    except Exception:
        return False

zodiac_list = [
    "Aries","Taurus","Gemini","Cancer","Leo","Virgo",
    "Libra","Scorpio","Sagittarius","Capricorn","Aquarius","Pisces"
]

def validate_zodiac(zodiac):
    try:
        return zodiac in zodiac_list
    except Exception:
        return False

# -----------------------------
# AUTO-ID
# -----------------------------
def get_next_id(filename="Storage_File/users.txt"):
    try:
        if not os.path.exists(filename):
            return 1
        with open(filename, "r") as file:
            lines = file.readlines()
        if not lines:
            return 1
        last_id = int(lines[-1].split(":")[0])
        return last_id + 1
    except Exception:
        print(f"{RED}Error reading user file. Using ID = 1.{RESET}")
        return 1

# -----------------------------
# HASH DATA USING BCRYPT
# -----------------------------
def hash_data(data):
    try:
        return bcrypt.hashpw(data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except Exception:
        print(f"{RED}Error hashing data.{RESET}")
        return ""

# -----------------------------
# SAVE USER
# -----------------------------
def save_user(user_id, username, password, color, pet, zodiac, filename="Storage_File/users.txt"):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "a") as file:
            file.write(f"{user_id}:{username}:{password}:{color}:{pet}:{zodiac}\n")
    except Exception:
        print(f"{RED}Error saving user data.{RESET}")

# -----------------------------
# CHECK UNIQUE USERNAME
# -----------------------------
def is_username_unique(username, filename="Storage_File/users.txt"):
    try:
        if not os.path.exists(filename):
            return True
        with open(filename, "r") as file:
            for line in file:
                parts = line.strip().split(":")
                if len(parts) > 1 and username.lower() == parts[1].lower():
                    return False
        return True
    except Exception:
        print(f"{RED}Error checking username uniqueness.{RESET}")
        return False

# -----------------------------
# REGISTER FUNCTION
# -----------------------------
def Register():
    try:
        os.system("cls")
        print("=== Create New Account ===\n")

        # ---- Username ----
        for attempt in range(3):
            print(f"\n{YELLOW}must be 4–8 characters(uppercase, lowercase, and number){RESET}")
            username = input("===> Enter username: ").strip()
            if not username or not validate_username(username):
                print(f"{RED}Invalid username! Attempts left: {2 - attempt}{RESET}")
                continue
            if not is_username_unique(username):
                print(f"{RED}Username already exists! Attempts left: {2 - attempt}{RESET}")
                continue
            break
        else:
            print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
            return

        # ---- Password ----
        for attempt in range(3):
            print(f"\n{YELLOW}must be more than 8 characters(uppercase, lowercase, number, and special character){RESET}")
            password = getpass.getpass("===> Enter password: ").strip()
            if not password or not validate_password(password):
                print(f"{RED}Invalid password! Attempts left: {2 - attempt} {RESET}")
                continue
            confirm_password = getpass.getpass("===> Confirm password: ").strip()
            if not confirm_password or password != confirm_password:
                print(f"{RED}Passwords do not match! Attempts left: {2 - attempt} {RESET}")
                continue
            break
        else:
            print(f"{RED}Maximum attempts reached. Exiting. {RESET}")
            return

        # ---- Color ----
        for attempt in range(3):
            print(f"\n{YELLOW}must be started with Capital letter{RESET}")
            color_input = masked_input("===> Enter your favorite color: ")
            if color_input and validate_pet_color(color_input):
                color = color_input
                break
            print(f"{RED}Invalid color! Attempts left: {2 - attempt} {RESET}")
        else:
            print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
            return

        # ---- Pet ----
        for attempt in range(3):
            print(f"\n{YELLOW}must be started with Capital letter{RESET}")
            pet_input = masked_input("===> Enter pet name: ")
            if pet_input and validate_pet_color(pet_input):
                pet = pet_input
                break
            print(f"{RED}Invalid pet name! Attempts left: {2 - attempt}{RESET}")
        else:
            print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
            return

        # ---- Zodiac ----
        print("\nValid zodiac signs:", zodiac_list)
        for attempt in range(3):
            print(f"{YELLOW}must be started with Capital letter{RESET}")
            zodiac_input = masked_input("===> Enter zodiac sign: ")
            if zodiac_input and validate_zodiac(zodiac_input):
                zodiac = zodiac_input
                break
            print(f"{RED}Invalid zodiac sign! Attempts left: {2 - attempt} {RESET}")
        else:
            print(f"{RED}Maximum attempts reached. Exiting.{RESET}")
            return

        print(f"\n{GREEN}You have been successfully create your account!.{RESET}")
        input("Press Any Key To Continue")

        # ---- Auto ID & Save ----
        user_id = get_next_id()

        hashed_password = hash_data(password)
        hashed_color = hash_data(color)
        hashed_pet = hash_data(pet)
        hashed_zodiac = hash_data(zodiac)

        save_user(user_id, username, hashed_password, hashed_color, hashed_pet, hashed_zodiac)

    except KeyboardInterrupt:
        print(f"\n{RED}Registration cancelled by user.{RESET}")
    except Exception:
        print(f"{RED}Unexpected error occurred during registration.{RESET}")
