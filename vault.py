from cryptography.fernet import Fernet, InvalidToken

from . import db, ui
from .crypto import derive_key, make_cipher, encrypt, decrypt, generate_salt
from .lockout import LockoutTracker
from .passwords import generate_password, check_strength

_lockout = LockoutTracker()

MAX_ATTEMPTS = 3


class VaultSession:
    def __init__(self, vault_id: int, vault_name: str, cipher: Fernet):
        self.vault_id = vault_id
        self.vault_name = vault_name
        self._cipher = cipher

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _encrypt(self, plaintext: str) -> str:
        return encrypt(self._cipher, plaintext)

    def _decrypt(self, ciphertext: str) -> str:
        return decrypt(self._cipher, ciphertext)

    def _pick_service(self, action: str) -> str:
        """Show all services and let the user pick by number. Returns service name or ''."""
        rows = db.fetch_all_passwords(self.vault_id)
        if not rows:
            ui.err("no passwords stored in this vault yet")
            return ""
        ui.section(f"Stored services in '{self.vault_name}'")
        names = [r[0] for r in rows]
        for i, name in enumerate(names, 1):
            print(f"  {i}. {name}")
        raw = input(f"\n{action} (enter number): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(names):
            return names[int(raw) - 1]
        ui.err("invalid selection")
        return ""

    # ------------------------------------------------------------------
    # password operations
    # ------------------------------------------------------------------

    def add_password(self) -> None:
        ui.header(f"Add password  [{self.vault_name}]")
        service = ui.prompt("Service name")
        if not service:
            ui.err("service name cannot be empty")
            return
        if db.service_exists(self.vault_id, service):
            ui.err(f"'{service}' already exists in this vault")
            return

        username = ui.prompt("Username / email")

        if ui.confirm("Generate a password"):
            length = ui.prompt_int("Length", 16)
            password = generate_password(length)
            print(f"\nGenerated: {password}")
        else:
            password = ui.secret("Password")

        result = check_strength(password)
        print(f"Strength: {result['label']}  ({result['entropy']} bits of entropy)")
        if result["issues"]:
            print("Suggestions: " + ", ".join(result["issues"]))

        notes = ui.prompt("Notes (optional)")
        db.insert_password(self.vault_id, service, username, self._encrypt(password), notes)
        ui.ok(f"'{service}' saved")

    def view_password(self) -> None:
        ui.header(f"View password  [{self.vault_name}]")
        service = self._pick_service("View entry")
        if not service:
            return
        row = db.fetch_password(self.vault_id, service)
        if not row:
            ui.err(f"no entry found for '{service}'")
            return
        username, enc_pw, notes, created_at, modified_at = row
        password = self._decrypt(enc_pw)
        print()
        print(f"  Service  : {service}")
        print(f"  Username : {username}")
        print(f"  Password : {password}")
        print(f"  Notes    : {notes or 'none'}")
        print(f"  Created  : {created_at[:10]}")
        print(f"  Modified : {modified_at[:10]}")

    def list_passwords(self) -> None:
        ui.header(f"All passwords  [{self.vault_name}]")
        rows = db.fetch_all_passwords(self.vault_id)
        if not rows:
            ui.err("no passwords stored yet")
            return

        print("  1. Show decrypted passwords (plaintext)")
        print("  2. Show encrypted passwords (raw stored value)")
        choice = input("\nSelect view mode: ").strip()
        if choice not in ("1", "2"):
            ui.err("invalid selection")
            return

        show_decrypted = choice == "1"

        for i, (service, username, enc_pw, notes, created_at, _) in enumerate(rows, 1):
            display_pw = self._decrypt(enc_pw) if show_decrypted else enc_pw
            print(f"\n  {i}. {service}")
            print(f"     username : {username}")
            print(f"     password : {display_pw}")
            print(f"     notes    : {notes or 'none'}")
            print(f"     created  : {created_at[:10]}")

    def search_passwords(self) -> None:
        ui.header(f"Search  [{self.vault_name}]")
        query = ui.prompt("Search term")
        results = db.search_services(self.vault_id, query)
        if not results:
            print("No matches found.")
            return
        print(f"\nFound {len(results)} match(es):")
        for service, username in results:
            print(f"  {service}  ({username})")

    def update_password(self) -> None:
        ui.header(f"Update password  [{self.vault_name}]")
        service = self._pick_service("Update entry")
        if not service:
            return
        row = db.fetch_password(self.vault_id, service)
        if not row:
            ui.err(f"no entry for '{service}'")
            return

        username, enc_pw, notes, _, _ = row
        current_password = self._decrypt(enc_pw)

        print(f"\nEditing '{service}'  (press Enter to keep current value)")

        new_username = input(f"  Username [{username}]: ").strip()
        username = new_username or username

        if ui.confirm("Change password"):
            if ui.confirm("Generate a new password"):
                length = ui.prompt_int("Length", 16)
                current_password = generate_password(length)
                print(f"  Generated: {current_password}")
            else:
                current_password = ui.secret("New password")
            result = check_strength(current_password)
            print(f"  Strength: {result['label']}  ({result['entropy']} bits)")

        new_notes = input(f"  Notes [{notes or ''}]: ").strip()
        notes = new_notes or notes

        db.update_password(self.vault_id, service, username, self._encrypt(current_password), notes)
        ui.ok(f"'{service}' updated")

    def delete_password(self) -> None:
        ui.header(f"Delete password  [{self.vault_name}]")
        service = self._pick_service("Delete entry")
        if not service:
            return
        if ui.confirm_destructive(f"Delete '{service}'"):
            db.delete_password(self.vault_id, service)
            ui.ok(f"'{service}' deleted")
        else:
            print("Cancelled.")

    def generate_standalone(self) -> None:
        ui.header("Generate password")
        length = ui.prompt_int("Length", 16)
        password = generate_password(length)
        result = check_strength(password)
        print(f"\nPassword : {password}")
        print(f"Strength : {result['label']}  ({result['entropy']} bits)")

    def export_vault(self) -> None:
        import json
        ui.header(f"Export  [{self.vault_name}]")
        rows = db.fetch_all_passwords(self.vault_id)
        if not rows:
            ui.err("nothing to export")
            return
        data = {}
        for service, username, enc_pw, notes, created_at, modified_at in rows:
            data[service] = {
                "username": username,
                "password": self._decrypt(enc_pw),
                "notes": notes,
                "created": created_at,
                "modified": modified_at,
            }
        default_name = f"{self.vault_name}_export.json"
        filename = input(f"Filename (default: {default_name}): ").strip() or default_name
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        ui.ok(f"exported to '{filename}'")
        ui.warn("this file is NOT encrypted — keep it safe")


# ------------------------------------------------------------------
# factory functions used by the CLI
# ------------------------------------------------------------------

def create_new_vault() -> VaultSession | None:
    ui.header("Create vault")
    name = ui.prompt("Vault name")
    if not name:
        ui.err("vault name cannot be empty")
        return None
    if db.vault_exists(name):
        ui.err(f"vault '{name}' already exists")
        return None

    while True:
        master = ui.secret("Master password (min 12 characters)")
        if len(master) < 12:
            ui.err("password must be at least 12 characters")
            continue
        confirm = ui.secret("Confirm master password")
        if master != confirm:
            ui.err("passwords do not match")
            continue
        break

    salt = generate_salt()
    key = derive_key(master, salt)
    vault_id = db.create_vault(name, salt)
    cipher = make_cipher(key)
    ui.ok(f"vault '{name}' created")
    return VaultSession(vault_id, name, cipher)


def open_existing_vault() -> VaultSession | None:
    vaults = db.list_vaults()
    if not vaults:
        print("No vaults found.")
        return None

    ui.header("Open vault")
    labels = []
    for vault_id, vault_name, created_at in vaults:
        locked, remaining = _lockout.is_locked(vault_id)
        if locked:
            m, s = remaining
            labels.append(f"{vault_name}  (created {created_at[:10]})  [locked {m}m {s}s]")
        else:
            labels.append(f"{vault_name}  (created {created_at[:10]})")

    idx = ui.pick_from_list(labels, "Select vault")
    if idx < 0:
        ui.err("invalid selection")
        return None

    vault_id, vault_name, _ = vaults[idx]

    locked, remaining = _lockout.is_locked(vault_id)
    if locked:
        m, s = remaining
        ui.err(f"vault is locked — try again in {m}m {s}s")
        return None

    salt = db.get_vault_salt(vault_id)
    if salt is None:
        ui.err("vault record not found")
        return None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        remaining_tries = MAX_ATTEMPTS - attempt + 1
        master = ui.secret(f"Master password for '{vault_name}' ({remaining_tries} attempt(s) left)")
        key = derive_key(master, salt)
        cipher = make_cipher(key)

        # Verify the key by attempting a decrypt.
        # If vault is empty we have no ciphertext to test against, so we accept the key
        # and the first add_password call will simply store with whatever key was given —
        # which is correct behaviour for a brand-new vault.
        probe = db.get_any_encrypted_password(vault_id)
        if probe is not None:
            try:
                decrypt(cipher, probe)
            except (InvalidToken, Exception):
                if attempt < MAX_ATTEMPTS:
                    ui.err(f"wrong password — {MAX_ATTEMPTS - attempt} attempt(s) remaining")
                    continue
                else:
                    minutes = _lockout.record_failed_session(vault_id)
                    sessions = _lockout.failed_session_count(vault_id)
                    ui.err(
                        f"access denied — vault locked for {minutes} minute(s)"
                    )
                    if sessions > 1:
                        print(f"  note: this is failed session #{sessions}; future lockouts will be longer")
                    return None

        # password accepted
        _lockout.reset(vault_id)
        ui.ok(f"vault '{vault_name}' opened")
        return VaultSession(vault_id, vault_name, cipher)

    return None
