import streamlit as st
import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "vault.json"

def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()

def load_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    return {}

def save_vault(vault):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=4)

def lock_vault():
    st.session_state.vault_unlocked = False
    st.session_state.vault_data = {}
    st.session_state.key = None
    st.rerun()

def main():
    st.title("Secure Password Vault")

    if "vault_unlocked" not in st.session_state:
        st.session_state.vault_unlocked = False
    if "vault_data" not in st.session_state:
        st.session_state.vault_data = {}
    if "key" not in st.session_state:
        st.session_state.key = None

    vault = load_vault()

    if not st.session_state.vault_unlocked:
        if not vault:
            st.info("No vault found. Set up your master password.")
            master_password = st.text_input("Create Master Password", type="password")
            confirm_password = st.text_input("Confirm Master Password", type="password")
            if st.button("Create Vault"):
                if master_password == confirm_password and master_password:
                    salt = os.urandom(16)
                    key = generate_key(master_password, salt)
                    vault = {
                        "salt": base64.urlsafe_b64encode(salt).decode(),
                        "data": []
                    }
                    save_vault(vault)
                    st.success("Vault created successfully! Please restart and unlock.")
                else:
                    st.error("Passwords do not match or are empty.")
        else:
            st.info("Enter your master password to unlock the vault.")
            master_password = st.text_input("Master Password", type="password")
            if st.button("Unlock Vault"):
                try:
                    salt = base64.urlsafe_b64decode(vault["salt"])
                    key = generate_key(master_password, salt)
                    st.session_state.key = key
                    st.session_state.vault_data = vault
                    st.session_state.vault_unlocked = True
                    st.success("Vault unlocked successfully!")
                    st.rerun()
                except Exception:
                    st.error("Incorrect password or vault corrupted.")
    else:
        st.sidebar.success("Vault Unlocked")
        st.sidebar.button("Lock Vault", on_click=lambda: lock_vault())

        st.subheader("Vault Options")
        choice = st.selectbox("Select an Option", ["Add Password", "View Vault"])

        if choice == "Add Password":
            site = st.text_input("Website / App Name")
            username = st.text_input("Username / Email")
            password = st.text_input("Password", type="password")
            if st.button("Add to Vault"):
                encrypted_password = encrypt_data(password, st.session_state.key)
                st.session_state.vault_data["data"].append({
                    "site": site,
                    "username": username,
                    "password": encrypted_password
                })
                save_vault(st.session_state.vault_data)
                st.success("Password added successfully!")

        elif choice == "View Vault":
            st.write("### Stored Passwords")
            for entry in st.session_state.vault_data["data"]:
                decrypted_password = decrypt_data(entry["password"], st.session_state.key)
                st.write(f"**Site:** {entry['site']}")
                st.write(f"Username: {entry['username']}")
                st.write(f"Password: {decrypted_password}")
                st.write("---")

if __name__ == "__main__":
    main()
