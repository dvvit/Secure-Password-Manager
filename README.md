# Password Manager

A CLI password manager with AES encryption, multiple vaults, and brute-force protection.

## Setup

```
pip install -r requirements.txt
```

## Run

```
python main.py
```

## Features

- Multiple isolated vaults, each with its own master password
- AES-256 encryption via Fernet; keys derived with PBKDF2-HMAC-SHA256 (100,000 iterations)
- Password strength analysis with entropy (bits) calculation
- Secure password generator using `secrets`
- Progressive lockout after failed authentication (3 → 5 → 10 → 30 → 60 minutes)
- SQLite storage; passwords never leave the database in plaintext
- JSON export (plaintext — handle with care)

## Project layout

```
main.py                   entry point
passmanager/
    __init__.py
    cli.py                menus and main loop
    vault.py              VaultSession class, open/create vault logic
    db.py                 all SQLite queries
    crypto.py             key derivation and Fernet helpers
    passwords.py          generation and strength / entropy analysis
    lockout.py            brute-force lockout tracker
    ui.py                 terminal I/O helpers
requirements.txt
```
