from . import db, ui
from .vault import create_new_vault, open_existing_vault


def vault_menu(session) -> None:
    options = [
        "Add password",
        "View password",
        "List all passwords",
        "Search passwords",
        "Update password",
        "Delete password",
        "Generate password",
        "Export vault",
        "Close vault",
    ]
    actions = [
        session.add_password,
        session.view_password,
        session.list_passwords,
        session.search_passwords,
        session.update_password,
        session.delete_password,
        session.generate_standalone,
        session.export_vault,
    ]

    while True:
        ui.header(f"Vault: {session.vault_name}")
        for i, label in enumerate(options, 1):
            print(f"  {i}. {label}")

        choice = input("\nSelect option: ").strip()
        if not choice.isdigit():
            ui.err("enter a number")
            continue
        n = int(choice)
        if n == len(options):
            print(f"\nClosing '{session.vault_name}'.")
            break
        if 1 <= n < len(options):
            actions[n - 1]()
        else:
            ui.err("invalid option")


def main() -> None:
    db.init_db()

    print("\nPassword Manager")
    print(ui.DIVIDER)

    while True:
        print("\n  1. Open vault")
        print("  2. Create vault")
        print("  3. Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            session = open_existing_vault()
            if session:
                vault_menu(session)
        elif choice == "2":
            session = create_new_vault()
            if session:
                vault_menu(session)
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            ui.err("invalid option")
