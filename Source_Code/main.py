import os
import time
import pyfiglet

from register import *
from login import *

while True:
    
    os.system("cls")
    try:
        Welcome_word = pyfiglet.figlet_format("Welcome to Password Managing", font="doom", width=200)
        print("\n" +f"{BLUE} {Welcome_word} {RESET}")
        print(f"{BLUE}={RESET}"*200)
        print("""
                            Menu: 
                    
                                1. Sign Up (New User)

                                2. Sign In

                                0. Exit 
                """)
        print(f"{BLUE}={RESET}"*200)
        opt = input(f"\n\tChoose an option (1-3): {RESET}")

        if opt == '' :
            raise ValueError(f"{RED}Input cannot be empty!{RESET}")
        
        opt = int(opt)

        if opt == 1 :
            Register()
        elif opt == 2:
            login()
            input("press any key to continue")                   
        elif opt == 0:
            os.system("cls")
            print(f"{BLUE}={RESET}"*200+"\n")
            print("Exit The Program ...\n")
            print(f"{BLUE}={RESET}"*200+"\n")
            time.sleep(1)
            os.system("cls")
            break
        else:
            os.system("cls")
            print(f"{BLUE}={RESET}"*200+"\n")
            print(f"{RED}The system was closed Invalid time{RESET}\n")
            print(f"{BLUE}={RESET}"*200+"\n")
            input(" "*170 + f"{RED}Exit{RESET}")

    except ValueError as e:
        print(f"\n\t{RED}Invalid input! Please enter a valid number. Error: {e}{RESET}")
        time.sleep(1)
        os.system('cls')



