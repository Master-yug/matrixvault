import os
import json
import bcrypt
import getpass
from cryptography.fernet import Fernet


def load_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    with open("key.key", "rb") as key_file:
        return Fernet(key_file.read())


def setup_master_password():
    hash_exists = os.path.exists("master.hash")
    key_exists = os.path.exists("key.key")

    if not hash_exists and key_exists:
        print("🚨 Security Alert: Encryption key exists but master password hash is missing.")
        print("🛑 Vault access blocked. Please delete key and vault manually to reset.")
        exit()

    if not hash_exists:
        print("🔐 No master password set. Let's create one.")
        while True:
            password = getpass.getpass("Set a master password: ")
            confirm = getpass.getpass("Confirm master password: ")
            if password != confirm:
                print("❌ Passwords do not match. Try again.")
            elif len(password) < 6:
                print("❌ Password too short. Use at least 6 characters.")
            else:
                break
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with open("master.hash", "wb") as f:
            f.write(hashed)
        print("✅ Master password created.\n")


def verify_master_password():
    if not os.path.exists("master.hash"):
        print("❌ Master password hash not found. Cannot continue.")
        return False

    with open("master.hash", "rb") as f:
        stored_hash = f.read()

    for attempt in range(3):
        password = getpass.getpass("Enter master password: ")
        if bcrypt.checkpw(password.encode(), stored_hash):
            print("✅ Access granted.\n")
            return True
        else:
            print("❌ Incorrect password.")
    print("🚫 Too many failed attempts. Exiting.")
    return False


def save_vault(data):
    try:
        with open("vault.json", "w") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"Error saving vault: {e}")


def load_vault():
    if not os.path.exists("vault.json"):
        return []
    with open("vault.json", "r") as f:
        return json.load(f)


def add_entry(fernet):
    website = input("Website: ").strip()
    username = input("Username/Email: ").strip()
    password = input("Password: ").strip()

    enc_password = fernet.encrypt(password.encode()).decode()

    entry = {
        "website": website,
        "username": username,
        "password": enc_password
    }

    data = load_vault()
    data.append(entry)
    save_vault(data)
    print("[+] Entry added.")


def view_entries(fernet):
    data = load_vault()
    if not data:
        print("🔒 Vault is empty.")
        return
    print("\nStored Passwords:")
    for idx, entry in enumerate(data, 1):
        print(f"{idx}. {entry['website']}")
        print(f"   Username: {entry['username']}")
        try:
            dec_password = fernet.decrypt(entry['password'].encode()).decode()
            print(f"   Password: {dec_password}")
        except:
            print("   🔐 Unable to decrypt password.")
        print("-" * 30)


def search_entries(fernet):
    keyword = input("Search by website/username: ").strip().lower()
    data = load_vault()
    results = [
        entry for entry in data
        if keyword in entry['website'].lower() or keyword in entry['username'].lower()
    ]
    if not results:
        print("🔎 No matching entries found.")
        return
    for idx, entry in enumerate(results, 1):
        print(f"{idx}. {entry['website']}")
        print(f"   Username: {entry['username']}")
        try:
            dec_password = fernet.decrypt(entry['password'].encode()).decode()
            print(f"   Password: {dec_password}")
        except:
            print("   🔐 Unable to decrypt password.")
        print("-" * 30)


def edit_entry(fernet):
    data = load_vault()
    website = input("Enter website to edit: ").strip().lower()
    found = False

    for entry in data:
        if entry['website'].lower() == website:
            print("Leave any field blank to keep it unchanged.")
            new_username = input(f"New username (current: {entry['username']}): ").strip()
            new_password = input("New password: ").strip()

            if new_username:
                entry['username'] = new_username
            if new_password:
                entry['password'] = fernet.encrypt(new_password.encode()).decode()

            found = True
            break

    if found:
        save_vault(data)
        print("[~] Entry updated.")
    else:
        print("❌ Entry not found.")


def delete_entry(fernet):
    data = load_vault()
    website = input("Enter website to delete: ").strip().lower()
    original_len = len(data)
    data = [entry for entry in data if entry['website'].lower() != website]

    if len(data) == original_len:
        print("❌ Entry not found.")
    else:
        save_vault(data)
        print("[x] Entry deleted.")


def main():
    setup_master_password()
    if not verify_master_password():
        return

    fernet = load_key()

    while True:
        print("\n🔐 Password Vault Menu:")
        print("1. Add new password")
        print("2. View stored passwords")
        print("3. Exit")
        print("4. Search for an entry")
        print("5. Edit an entry")
        print("6. Delete an entry")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            add_entry(fernet)
        elif choice == "2":
            view_entries(fernet)
        elif choice == "3":
            print("👋 Goodbye!")
            break
        elif choice == "4":
            search_entries(fernet)
        elif choice == "5":
            edit_entry(fernet)
        elif choice == "6":
            delete_entry(fernet)
        else:
            print("❌ Invalid option. Try again.")


if __name__ == "__main__":
    main()

