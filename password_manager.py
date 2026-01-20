import json
import base64
import os
import secrets
import string
import hashlib
import sqlite3
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta
import re

class PasswordManager:
    def __init__(self):
        self.db_file = "password_vaults.db"
        self.cipher = None
        self.current_vault_id = None
        self.current_vault_name = None
        self.failed_attempts = {}  # {vault_id: [attempt_count, lockout_until]}
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create vaults table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vaults (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_name TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id INTEGER NOT NULL,
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL,
                modified_at TEXT NOT NULL,
                FOREIGN KEY (vault_id) REFERENCES vaults (id),
                UNIQUE(vault_id, service_name)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def derive_key(self, master_password, salt):
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def check_lockout(self, vault_id, vault_name):
        """Check if vault is locked out and return remaining time"""
        if vault_id not in self.failed_attempts:
            return False, 0
        
        attempt_count, lockout_until = self.failed_attempts[vault_id]
        
        if lockout_until is None:
            return False, 0
        
        current_time = datetime.now()
        if current_time < lockout_until:
            remaining_seconds = (lockout_until - current_time).total_seconds()
            remaining_minutes = int(remaining_seconds / 60)
            remaining_secs = int(remaining_seconds % 60)
            return True, (remaining_minutes, remaining_secs)
        else:
            # Lockout expired, reset to 0 attempts but keep history
            self.failed_attempts[vault_id] = [0, None]
            return False, 0
    
    def calculate_lockout_time(self, attempt_count):
        """Calculate lockout duration based on failed attempts"""
        lockout_durations = {
            1: 1,    # 1 minute
            2: 5,    # 5 minutes
            3: 15,   # 15 minutes
            4: 30,   # 30 minutes
            5: 60,   # 1 hour
        }
        minutes = lockout_durations.get(attempt_count, 120)  # 2 hours for 6+ attempts
        return timedelta(minutes=minutes)
    
    def record_failed_attempt(self, vault_id):
        """Record a failed authentication attempt"""
        if vault_id not in self.failed_attempts:
            self.failed_attempts[vault_id] = [0, None]
        
        attempt_count, _ = self.failed_attempts[vault_id]
        attempt_count += 1
        
        lockout_duration = self.calculate_lockout_time(attempt_count)
        lockout_until = datetime.now() + lockout_duration
        
        self.failed_attempts[vault_id] = [attempt_count, lockout_until]
        
        return lockout_duration.total_seconds() / 60  # Return minutes
    
    def reset_failed_attempts(self, vault_id):
        """Reset failed attempts after successful authentication"""
        if vault_id in self.failed_attempts:
            self.failed_attempts[vault_id] = [0, None]
    
    def get_password_input(self, prompt):
        """Get password input that works in all environments"""
        print(prompt, end='', flush=True)
        password = input()
        return password
        """Get password input that works in all environments"""
        print(prompt, end='', flush=True)
        password = input()
        return password
    
    def list_vaults(self):
        """List all existing vaults"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT id, vault_name, created_at FROM vaults ORDER BY created_at DESC')
        vaults = cursor.fetchall()
        conn.close()
        return vaults
    
    def create_vault(self):
        """Create a new vault"""
        print("\n=== Create New Vault ===")
        
        vault_name = input("Enter vault name: ").strip()
        if not vault_name:
            print("ERROR: Vault name cannot be empty!")
            return False
        
        # Check if vault already exists
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM vaults WHERE vault_name = ?', (vault_name,))
        if cursor.fetchone():
            conn.close()
            print(f"ERROR: Vault '{vault_name}' already exists!")
            return False
        
        # Get master password
        while True:
            master_pass = self.get_password_input("Create master password (min 8 chars): ")
            if len(master_pass) < 8:
                print("ERROR: Password must be at least 8 characters long!")
                continue
            
            confirm_pass = self.get_password_input("Confirm master password: ")
            if master_pass != confirm_pass:
                print("ERROR: Passwords don't match! Try again.")
                continue
            break
        
        # Generate random salt
        salt = os.urandom(16)
        key = self.derive_key(master_pass, salt)
        
        # Store vault in database
        cursor.execute('''
            INSERT INTO vaults (vault_name, salt, created_at)
            VALUES (?, ?, ?)
        ''', (vault_name, salt, datetime.now().isoformat()))
        
        vault_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        self.cipher = Fernet(key)
        self.current_vault_id = vault_id
        self.current_vault_name = vault_name
        
        print(f"SUCCESS: Vault '{vault_name}' created successfully!\n")
        return True
    
    def open_vault(self):
        """Open an existing vault"""
        vaults = self.list_vaults()
        
        if not vaults:
            print("\nNo vaults found!")
            return False
        
        print("\n=== Available Vaults ===")
        for idx, (vault_id, vault_name, created_at) in enumerate(vaults, 1):
            # Check if vault is locked
            is_locked, remaining = self.check_lockout(vault_id, vault_name)
            if is_locked:
                minutes, seconds = remaining
                print(f"{idx}. {vault_name} (created: {created_at[:10]}) [LOCKED - {minutes}m {seconds}s remaining]")
            else:
                print(f"{idx}. {vault_name} (created: {created_at[:10]})")
        
        choice = input("\nSelect vault number: ").strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(vaults):
            print("ERROR: Invalid selection!")
            return False
        
        selected_vault = vaults[int(choice) - 1]
        vault_id, vault_name, _ = selected_vault
        
        # Check if vault is locked
        is_locked, remaining = self.check_lockout(vault_id, vault_name)
        if is_locked:
            minutes, seconds = remaining
            print(f"\nERROR: Vault '{vault_name}' is temporarily locked!")
            print(f"Please try again in {minutes} minute(s) and {seconds} second(s).")
            print("This is a security measure after multiple failed login attempts.")
            return False
        
        # Get salt from database
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT salt FROM vaults WHERE id = ?', (vault_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            print("ERROR: Vault not found!")
            return False
        
        salt = result[0]
        
        # Authenticate
        attempts = 3
        while attempts > 0:
            master_pass = self.get_password_input(f"Enter master password for '{vault_name}' ({attempts} attempts left): ")
            key = self.derive_key(master_pass, salt)
            self.cipher = Fernet(key)
            
            # Try to decrypt a test to verify password
            try:
                # Test decryption by trying to load passwords
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                cursor.execute('SELECT encrypted_password FROM passwords WHERE vault_id = ? LIMIT 1', (vault_id,))
                test_row = cursor.fetchone()
                conn.close()
                
                if test_row:
                    # Try to decrypt to verify password is correct
                    self.cipher.decrypt(test_row[0].encode())
                
                self.current_vault_id = vault_id
                self.current_vault_name = vault_name
                self.reset_failed_attempts(vault_id)  # Reset on successful login
                print(f"SUCCESS: Vault '{vault_name}' opened successfully!\n")
                return True
            except Exception:
                attempts -= 1
                if attempts > 0:
                    print(f"ERROR: Incorrect password! {attempts} attempts remaining.")
                else:
                    # Record failed attempt and calculate lockout
                    lockout_minutes = self.record_failed_attempt(vault_id)
                    print("ERROR: Access denied. Too many failed attempts.")
                    print(f"Vault '{vault_name}' is now locked for {int(lockout_minutes)} minute(s).")
                    
                    # Show lockout history
                    attempt_count, _ = self.failed_attempts[vault_id]
                    if attempt_count > 1:
                        print(f"Warning: This is your {attempt_count} failed authentication session.")
                        print("Future lockouts will be longer.")
                    
                    return False
        
        # If no passwords exist yet, accept the master password (new vault scenario)
        self.current_vault_id = vault_id
        self.current_vault_name = vault_name
        self.reset_failed_attempts(vault_id)
        print(f"SUCCESS: Vault '{vault_name}' opened successfully!\n")
        return True
    
    def check_password_strength(self, password):
        """Check password strength and return score"""
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password too short (min 8 chars)")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        strength = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
        return strength[min(score, 5)], feedback
    
    def generate_password(self, length=16, use_symbols=True, use_numbers=True, use_uppercase=True):
        """Generate a secure random password"""
        chars = string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_numbers:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password
    
    def add_password(self):
        """Add a new password entry"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        print(f"\n=== Add New Password to '{self.current_vault_name}' ===")
        service = input("Service/Website name: ").strip()
        
        if not service:
            print("ERROR: Service name cannot be empty!")
            return
        
        # Check if service already exists in this vault
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM passwords WHERE vault_id = ? AND service_name = ?', 
                      (self.current_vault_id, service))
        if cursor.fetchone():
            conn.close()
            print(f"ERROR: Entry for '{service}' already exists in this vault!")
            return
        
        username = input("Username/Email: ").strip()
        
        choice = input("Generate password? (y/n): ").lower()
        if choice == 'y':
            length = input("Password length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            password = self.generate_password(length)
            print(f"\nGenerated Password: {password}")
        else:
            password = self.get_password_input("Password: ")
        
        strength, feedback = self.check_password_strength(password)
        print(f"\nPassword Strength: {strength}")
        if feedback:
            print("Suggestions:", ", ".join(feedback))
        
        notes = input("Notes (optional): ").strip()
        
        # Encrypt password
        encrypted_password = self.cipher.encrypt(password.encode()).decode()
        
        # Store in database
        cursor.execute('''
            INSERT INTO passwords (vault_id, service_name, username, encrypted_password, notes, created_at, modified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (self.current_vault_id, service, username, encrypted_password, notes, 
              datetime.now().isoformat(), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        print(f"SUCCESS: Password for '{service}' saved successfully!")
    
    def view_password(self):
        """View a specific password"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT service_name FROM passwords WHERE vault_id = ?', (self.current_vault_id,))
        services = cursor.fetchall()
        
        if not services:
            print("\nERROR: No passwords stored in this vault yet!")
            conn.close()
            return
        
        print(f"\n=== Stored Services in '{self.current_vault_name}' ===")
        for i, (service,) in enumerate(services, 1):
            print(f"{i}. {service}")
        
        service = input("\nEnter service name: ").strip()
        
        cursor.execute('''
            SELECT username, encrypted_password, notes, created_at
            FROM passwords WHERE vault_id = ? AND service_name = ?
        ''', (self.current_vault_id, service))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            username, encrypted_password, notes, created_at = result
            password = self.cipher.decrypt(encrypted_password.encode()).decode()
            
            print(f"\n{'='*50}")
            print(f"Service: {service}")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print(f"Notes: {notes or 'N/A'}")
            print(f"Created: {created_at}")
            print(f"{'='*50}")
        else:
            print(f"ERROR: No entry found for '{service}'")
    
    def list_passwords(self):
        """List all stored services"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT service_name, username, encrypted_password, notes, created_at
            FROM passwords WHERE vault_id = ?
            ORDER BY service_name
        ''', (self.current_vault_id,))
        
        passwords = cursor.fetchall()
        conn.close()
        
        if not passwords:
            print("\nERROR: No passwords stored in this vault yet!")
            return
        
        print(f"\n=== All Passwords in '{self.current_vault_name}' ===")
        for i, (service, username, encrypted_password, notes, created_at) in enumerate(passwords, 1):
            password = self.cipher.decrypt(encrypted_password.encode()).decode()
            print(f"\n{i}. {service}")
            print(f"   Username: {username}")
            print(f"   Password: {password}")
            print(f"   Notes: {notes or 'N/A'}")
            print(f"   Created: {created_at[:10]}")
    
    def search_passwords(self):
        """Search passwords by service name"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        query = input("\nEnter search term: ").strip().lower()
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT service_name FROM passwords 
            WHERE vault_id = ? AND LOWER(service_name) LIKE ?
        ''', (self.current_vault_id, f'%{query}%'))
        
        results = cursor.fetchall()
        conn.close()
        
        if results:
            print(f"\n=== Found {len(results)} match(es) ===")
            for (service,) in results:
                print(f"- {service}")
        else:
            print("ERROR: No matches found!")
    
    def update_password(self):
        """Update an existing password"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        service = input("\nEnter service name to update: ").strip()
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, encrypted_password, notes
            FROM passwords WHERE vault_id = ? AND service_name = ?
        ''', (self.current_vault_id, service))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            print(f"ERROR: No entry found for '{service}'")
            return
        
        username, encrypted_password, notes = result
        password = self.cipher.decrypt(encrypted_password.encode()).decode()
        
        print(f"\nUpdating '{service}'")
        print("Press Enter to keep current value")
        
        new_username = input(f"Username [{username}]: ").strip()
        if new_username:
            username = new_username
        
        if input("Update password? (y/n): ").lower() == 'y':
            choice = input("Generate new password? (y/n): ").lower()
            if choice == 'y':
                password = self.generate_password()
                print(f"Generated: {password}")
            else:
                password = self.get_password_input("New password: ")
        
        new_notes = input(f"Notes [{notes or ''}]: ").strip()
        if new_notes:
            notes = new_notes
        
        # Encrypt new password
        encrypted_password = self.cipher.encrypt(password.encode()).decode()
        
        # Update in database
        cursor.execute('''
            UPDATE passwords 
            SET username = ?, encrypted_password = ?, notes = ?, modified_at = ?
            WHERE vault_id = ? AND service_name = ?
        ''', (username, encrypted_password, notes, datetime.now().isoformat(), 
              self.current_vault_id, service))
        
        conn.commit()
        conn.close()
        
        print(f"SUCCESS: '{service}' updated successfully!")
    
    def delete_password(self):
        """Delete a password entry"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        service = input("\nEnter service name to delete: ").strip()
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id FROM passwords WHERE vault_id = ? AND service_name = ?
        ''', (self.current_vault_id, service))
        
        if cursor.fetchone():
            confirm = input(f"WARNING: Delete '{service}'? (yes/no): ").lower()
            if confirm == 'yes':
                cursor.execute('''
                    DELETE FROM passwords WHERE vault_id = ? AND service_name = ?
                ''', (self.current_vault_id, service))
                conn.commit()
                conn.close()
                print(f"SUCCESS: '{service}' deleted successfully!")
            else:
                conn.close()
                print("Deletion cancelled.")
        else:
            conn.close()
            print(f"ERROR: No entry found for '{service}'")
    
    def export_vault(self):
        """Export current vault to JSON file"""
        if not self.current_vault_id:
            print("ERROR: No vault opened!")
            return
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT service_name, username, encrypted_password, notes, created_at, modified_at
            FROM passwords WHERE vault_id = ?
        ''', (self.current_vault_id,))
        
        passwords = cursor.fetchall()
        conn.close()
        
        if not passwords:
            print("\nERROR: No passwords to export!")
            return
        
        export_data = {}
        for service, username, encrypted_password, notes, created_at, modified_at in passwords:
            password = self.cipher.decrypt(encrypted_password.encode()).decode()
            export_data[service] = {
                "username": username,
                "password": password,
                "notes": notes,
                "created": created_at,
                "modified": modified_at
            }
        
        filename = input(f"Export filename (default: {self.current_vault_name}_export.json): ").strip()
        filename = filename if filename else f"{self.current_vault_name}_export.json"
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"SUCCESS: Vault exported to '{filename}'")
        print("WARNING: This file is NOT encrypted!")
    
    def vault_menu(self):
        """Vault operations menu"""
        while True:
            print("\n" + "="*50)
            print(f"Current Vault: {self.current_vault_name}")
            print("="*50)
            print("1. Add Password")
            print("2. View Password")
            print("3. List All Passwords")
            print("4. Search Passwords")
            print("5. Update Password")
            print("6. Delete Password")
            print("7. Generate Password")
            print("8. Export Vault")
            print("9. Close Vault")
            print("="*50)
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.add_password()
            elif choice == '2':
                self.view_password()
            elif choice == '3':
                self.list_passwords()
            elif choice == '4':
                self.search_passwords()
            elif choice == '5':
                self.update_password()
            elif choice == '6':
                self.delete_password()
            elif choice == '7':
                length = input("Password length (default 16): ").strip()
                length = int(length) if length.isdigit() else 16
                password = self.generate_password(length)
                print(f"\nGenerated Password: {password}")
                strength, _ = self.check_password_strength(password)
                print(f"Strength: {strength}")
            elif choice == '8':
                self.export_vault()
            elif choice == '9':
                print(f"\nClosing vault '{self.current_vault_name}'...")
                self.current_vault_id = None
                self.current_vault_name = None
                self.cipher = None
                break
            else:
                print("ERROR: Invalid option!")
    
    def run(self):
        """Main application loop"""
        print("="*50)
        print("   SECURE PASSWORD MANAGER")
        print("="*50)
        
        # Main loop - allows going back after failed attempts
        while True:
            print("\n=== Main Menu ===")
            print("\n1. Open existing vault")
            print("2. Create new vault")
            print("3. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                if self.open_vault():
                    self.vault_menu()
                # If open_vault fails, loop continues and user can try again
            elif choice == '2':
                if self.create_vault():
                    self.vault_menu()
                # If create_vault fails, loop continues
            elif choice == '3':
                print("\nGoodbye! Stay secure!")
                break
            else:
                print("ERROR: Invalid option!")

if __name__ == "__main__":
    manager = PasswordManager()
    manager.run()