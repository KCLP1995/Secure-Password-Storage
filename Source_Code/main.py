import os
import time
import pyfiglet

from register import *
from login import *

while True:
    
    os.system("cls")
    try:
        # ----------------------------
        # Display Welcome Message
        # ----------------------------
        try:
            Welcome_word = pyfiglet.figlet_format("Welcome to Secure Password Storage", font="doom", width=200)
        except Exception as e:
            # Fallback if pyfiglet fails
            Welcome_word = "Welcome to Password Managing"
            print(f"{RED}Error displaying fancy text: {e}{RESET}")
        
        print("\n" + f"{BLUE} {Welcome_word} {RESET}")
        print(f"{BLUE}={RESET}"*170)
        print("""
                            Menu: 
                    
                                1. Sign Up (New User)

                                2. Sign In

                                0. Exit 
                """)
        print(f"{BLUE}={RESET}"*170)

        # ----------------------------
        # User Input
        # ----------------------------
        opt = input(f"\n\tChoose an option (1-3): {RESET}").strip()
        if not opt:
            raise ValueError(f"{RED}Input cannot be empty!{RESET}")
        
        try:
            opt = int(opt)
        except ValueError:
            raise ValueError(f"{RED}Input must be a number!{RESET}")
        
        # ----------------------------
        # Menu Options
        # ----------------------------
        if opt == 1:
            try:
                Register()
            except Exception as e:
                print(f"{RED}Error during registration: {e}{RESET}")
                time.sleep(1)
        elif opt == 2:
            try:
                login()
                input("Press any key to continue")
            except Exception as e:
                print(f"{RED}Error during login: {e}{RESET}")
                time.sleep(1)                  
        elif opt == 0:
            os.system("cls")
            print(f"{BLUE}={RESET}"*170+"\n")
            print("Exit The Program ...\n")
            print(f"{BLUE}={RESET}"*170+"\n")
            time.sleep(1)
            os.system("cls")
            break
        else:
            os.system("cls")
            print(f"{BLUE}={RESET}"*170+"\n")
            print(f"{RED}Invalid option. Please enter 0, 1, or 2.{RESET}\n")
            print(f"{BLUE}={RESET}"*170+"\n")
            input(" "*170 + f"{RED}Exit{RESET}")

    # ----------------------------
    # Catch top-level input errors
    # ----------------------------
    except ValueError as e:
        print(f"\n\t{RED}Invalid input! {e}{RESET}")
        time.sleep(1)
        os.system('cls')
    except KeyboardInterrupt:
        print(f"\n{RED}Program interrupted by user. Exiting...{RESET}")
        time.sleep(1)
        os.system('cls')
        break
    except Exception as e:
        print(f"\n{RED}Unexpected error occurred: {e}{RESET}")
        time.sleep(1)
        os.system('cls')
