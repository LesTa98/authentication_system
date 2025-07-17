# Python CLI User Authentication System

This is a simple command-line user authentication system built with Python. It allows users to:

- Register new accounts
- Log in with a username and password
- Change their password

Passwords are hashed securely using `bcrypt` and stored in a local text file.

## Features

- User registration
- Password authentication
- Change password
- Password hashing with bcrypt
- Password policy enforcement
- Local file-based storage (`password_check.txt`)

## Password Policy

To register or change a password, the password must meet the following criteria:

- Length between 8 and 12 characters
- At least 2 lowercase letters
- At least 2 uppercase letters
- At least 1 digit
- At least 1 special character

## Requirements

- Python 3.x
- bcrypt

Install dependencies using:

```bash
pip install -r requirements.txt
