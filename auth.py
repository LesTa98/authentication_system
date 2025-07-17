import re
import bcrypt
import csv
import sys
import logging
from pathlib import Path

# logging setup
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(messages)s')

# file to store credentials
password_file = Path(__file__).with_name('password_check.txt')
password_file.touch(exist_ok=True) #create the file if it doesn't exist

# hash password using bcrypt
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# check if the password matches hashed value
def verify_password(password: str, hashed:str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# reads user data
def read_file()-> dict:
    users = {}
    with password_file.open('r') as f:
        for line in f:
            if "," in line:
                username, hashed_pw = line.strip().split(',',1)
                users[username] = hashed_pw
    return users

# enforce password policy
def password_policy(password: str) -> bool:
    pattern =re.compile(r"(?=(.*[a-z]){2,})(?=(.*[A-Z]){2,})(?=(.*[0-9]){1,})")
    special_chars = "!@#$%^&*()-+?_=,<>/`\\/.}]{[\"']"
    return(
        8 <= len(password) <= 12 and
        any (char in special_chars for char in password) and pattern.match(password)
    )

# register user
def register(username: str, password1: str, password2: str):
    users = read_file()
    if username in users:
        logging.error("User already exists.")
        return

    if password1 != password2:
        logging.error("Passwords do not match.")
        return

    if not password_policy(password1):
            logging.error("Password does not meet policy requirements.")
            return

    hashed_pw = hash_password(password1).decode('utf-8')
    with password_file.open('a') as f:
        f.write(f"{username}, {hashed_pw}\n")


    logging.info("User registered successfully.")

# authenticate user
def authenticate(username: str, password: str):
    users = read_file()
    if username not in users:
        logging.error("No such user.")
        return

    hashed_pw = users[username]
    if verify_password(password, hashed_pw):
        logging.info("Login successful.")
    else:
        logging.error("Incorrect password.")

def change_password(username:str, old_password:str, new_password: str):
    users =read_file()

    if username not in users:
        logging.error("No such user.")
        return

    if not verify_password(old_password, users[username]):
        logging.error("Incorrect current password.")
        return

    if not password_policy(new_password):
        logging.error("New password does not meet the policy requirements")
        return

    users[username] = hash_password(new_password).decode('utf-8')

    with password_file.open('w', newline="") as f:
         writer = csv.writer(f)
         for user, pw in users.items():
             writer.writerow([user, pw])

    logging.info("Password changed successfully.")

# CLI interface
def main():
    args = sys.argv[1:]
    if not args:
        print("Usage:\n"
              "  register <username> <password1> <password2>\n"
              "  authenticate <username> <password>\n"
              "  changepassword <username> <old_password> <new_password>")
        return

    cmd = args[0].lower()
    try:
        if cmd == "register" and len(args)==4:
            register(args[1], args[2], args[3])
        elif cmd == "authenticate" and len(args) ==3:
            authenticate(args[1], args[2])
        elif cmd == "changepassword" and len(args)==4:
            change_password(args[1],args[2],args[3])
        else:
            logging.error("Invalid command or wrong number of arguments.")
    except Exception as e:
        logging.exception("An unexpected error occured.")

if __name__ == "__main__":
    main()

