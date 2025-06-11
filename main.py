import json
import os
import getpass
import bcrypt
import base64
import argparse
import threading
import sys
from cryptography.fernet import Fernet
from datetime import datetime

VAULT_FILE = "vault.json"
KEY_FILE = "key.key"
HASH_FILE = "master.hash"

# --- Utility Functions ---
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return Fernet(key)

def load_key():
    try:
        with open(KEY_FILE, 'rb') as key_file:
            return Fernet(key_file.read())
    except FileNotFoundError:
        print("Encryption key not found. Vault might be reset or uninitialized.")
        return None

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("Failed to load vault: file may be corrupted.")
        return []

def save_vault(data):
    try:
        with open(VAULT_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving vault: {e}")

# --- Ideal timeout feature --- 
IDLE_TIMEOUT = 180  # seconds (3 minutes)
idle_timer = None

def reset_idle_timer():
    global idle_timer
    if idle_timer:
        idle_timer.cancel()
    idle_timer = threading.Timer(IDLE_TIMEOUT, handle_idle_timeout)
    idle_timer.daemon = True
    idle_timer.start()

def handle_idle_timeout():
    print("\n🔒 Session locked due to inactivity.")
    os._exit(0)


# --- CLI Features ---
def export_vault(filename):
    if not os.path.exists(VAULT_FILE):
        print("Nothing to export. Vault is empty.")
        return
    try:
        with open(VAULT_FILE, 'r') as vf:
            content = vf.read()
        with open(filename, 'w') as ef:
            ef.write(content)
        print(f"✅ Vault exported to {filename}")
    except Exception as e:
        print(f"❌ Failed to export vault: {e}")

def import_vault(filename):
    try:
        with open(filename, 'r') as f:
            content = json.load(f)
            if not isinstance(content, list):
                print("❌ Invalid vault format.")
                return
        save_vault(content)
        print("✅ Vault imported successfully.")
    except Exception as e:
        print(f"❌ Failed to import vault: {e}")

def confirm_and_reset():
    print("⚠️  This will delete all data, key, and master password. This action is irreversible!")
    confirm1 = input("Type 'RESET' to confirm: ")
    if confirm1.strip().upper() != 'RESET':
        print("Reset cancelled.")
        return

    for file in [VAULT_FILE, KEY_FILE, HASH_FILE]:
        if os.path.exists(file):
            os.remove(file)
    print("✅ Vault, key, and master password have been reset.")

# --- CLI Parser ---
def handle_cli_args():
    parser = argparse.ArgumentParser(description="Password Vault Manager")
    parser.add_argument("--export", metavar="FILENAME", help="Export vault to a file")
    parser.add_argument("--import", dest="import_file", metavar="FILENAME", help="Import vault from a file")
    parser.add_argument("--reset", action="store_true", help="Reset the entire vault system")
    return parser.parse_args()

# --- Main Menu Interface ---
def authenticate():
    if not os.path.exists(HASH_FILE):
        print("Setting up new master password...")
        while True:
            password = getpass.getpass("Set a master password: ").strip()
            if len(password) < 8:
                print("❌ Master password must be at least 8 characters long. Try again.")
            else:
                break
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with open(HASH_FILE, 'wb') as f:
            f.write(hashed)
        print("✅ Master password set.")
    else:
        with open(HASH_FILE, 'rb') as f:
            hashed = f.read()
        for _ in range(3):
            password = getpass.getpass("Enter master password: ").encode()
            if bcrypt.checkpw(password, hashed):
                print("✅ Access granted.\n")
                return True
            else:
                print("❌ Incorrect password.")
        print("❌ Too many failed attempts.")
        return False


def ensure_key():
    if not os.path.exists(KEY_FILE):
        print("🔐 No encryption key found. Generating new key...")
        generate_key()
    return load_key()

def add_entry(vault, fernet):
    site = input("Website: ")
    user = input("Username/Email: ")
    pwd = input("Password: ")
    encrypted_pwd = fernet.encrypt(pwd.encode()).decode()
    vault.append({"website": site, "username": user, "password": encrypted_pwd, "last_updated": datetime.now().isoformat()})
    save_vault(vault)
    print("[+] Entry added.\n")

def view_entries(vault, fernet):
    if not vault:
        print("🔒 Vault is empty.\n")
        return
    for i, entry in enumerate(vault, 1):
        pwd = fernet.decrypt(entry['password'].encode()).decode()
        print(f"[{i}] {entry['website']} | {entry['username']} | {pwd} | Last updated: {entry.get('last_updated', 'N/A')}")
    print()

def search_entry(vault, fernet):
    term = input("Enter website or username to search: ").lower()
    results = [e for e in vault if term in e['website'].lower() or term in e['username'].lower()]
    if not results:
        print("🔍 No matching entries found.\n")
        return
    for entry in results:
        pwd = fernet.decrypt(entry['password'].encode()).decode()
        print(f"🔎 {entry['website']} | {entry['username']} | {pwd} | Last updated: {entry.get('last_updated', 'N/A')}")
    print()

def edit_entry(vault, fernet):
    view_entries(vault, fernet)
    try:
        idx = int(input("Enter the entry number to edit: ")) - 1
        if not (0 <= idx < len(vault)):
            print("Invalid entry number.")
            return
        site = input(f"New Website (leave blank to keep '{vault[idx]['website']}'): ") or vault[idx]['website']
        user = input(f"New Username/Email (leave blank to keep '{vault[idx]['username']}'): ") or vault[idx]['username']
        pwd = input("New Password (leave blank to keep current): ")
        encrypted_pwd = vault[idx]['password'] if pwd.strip() == '' else fernet.encrypt(pwd.encode()).decode()

        vault[idx].update({
            "website": site,
            "username": user,
            "password": encrypted_pwd,
            "last_updated": datetime.now().isoformat()
        })
        save_vault(vault)
        print("✅ Entry updated.\n")
    except ValueError:
        print("Invalid input.")

def delete_entry(vault, fernet):
    if not vault:
        print("🔒 Vault is empty.\n")
        return

    view_entries(vault, fernet)

    try:
        index = int(input("Enter the entry number to delete: "))
        if index < 1 or index > len(vault):
            print("❌ Invalid entry number.")
            return

        entry = vault[index - 1]
        confirm = input(f"⚠️ Are you sure you want to delete '{entry['website']}'? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("❌ Deletion cancelled.")
            return

        del vault[index - 1]
        save_vault(vault)
        print("✅ Entry deleted successfully.\n")

    except ValueError:
        print("❌ Please enter a valid number.")


def main():
    if not authenticate():
        return

    fernet = ensure_key()
    if not fernet:
        return

    vault = load_vault()

    while True:
        reset_idle_timer()
        print("\n🔐 Password Vault Menu:")
        print("1. Add new password")
        print("2. View stored passwords")
        print("3. Exit")
        print("4. Search for an entry")
        print("5. Edit an entry")
        print("6. Delete an entry")
        choice = input("Enter your choice: ")

        if choice == '1':
            add_entry(vault, fernet)
        elif choice == '2':
            view_entries(vault, fernet)
        elif choice == '3':
            print("Goodbye!")
            break
        elif choice == '4':
            search_entry(vault, fernet)
        elif choice == '5':
            edit_entry(vault, fernet)
        elif choice == '6':
            delete_entry(vault, fernet)
        else:
            print("Invalid choice.")

# --- Entry Point ---
if __name__ == "__main__":
    args = handle_cli_args()

    if args.reset:
        confirm_and_reset()
    elif args.export:
        export_vault(args.export)
    elif args.import_file:
        import_vault(args.import_file)
    else:
        main()

