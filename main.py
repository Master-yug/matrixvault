import os
import json
from cryptography.fernet import Fernet

KEY_FILE = "key.key"
VAULT_FILE = "vault.json"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print("[✔] New encryption key generated and saved.")
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        print("[!] Encryption key not found.")
        choice = input("Do you want to generate a new key? (Old data will be deleted) [y/n]: ").lower()
        if choice == 'y':
            if os.path.exists(VAULT_FILE):
                os.remove(VAULT_FILE)
            return generate_key()
        else:
            print("Exiting without key.")
            exit()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def save_vault(data, fernet):
    try:
        json_data = json.dumps(data).encode()
        encrypted_data = fernet.encrypt(json_data)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error saving vault: {e}")

def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return []
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data)
    except Exception as e:
        print("❌ Could not decrypt vault. Is the key correct or was the file tampered with?")
        exit()

def add_entry(fernet):
    website = input("Website: ")
    username = input("Username/Email: ")
    password = input("Password: ")

    entry = {"website": website, "username": username, "password": password}
    vault = load_vault(fernet)
    vault.append(entry)
    save_vault(vault, fernet)
    print("[+] Entry added.")

def view_entries(fernet):
    vault = load_vault(fernet)
    if not vault:
        print("Vault is empty.")
        return

    for i, entry in enumerate(vault, 1):
        print(f"\n[{i}]")
        print(f"Website: {entry['website']}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")

def main():
    key = load_key()
    fernet = Fernet(key)

    while True:
        print("\n--- Password Manager ---")
        print("1. Add new password")
        print("2. View stored passwords")
        print("3. Exit")

        choice = input("Choose an option: ").strip()
        if choice == "1":
            add_entry(fernet)
        elif choice == "2":
            view_entries(fernet)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()

