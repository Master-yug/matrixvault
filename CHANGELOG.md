Phase 2 Changelog
  1. Master Password System (with bcrypt)
      Added setup_master_password(): prompts the user to create a strong master password if not already set.
      Password validation: requires a minimum length of 6 characters and confirmation.
      Password hashing: securely stores master password hash using bcrypt.
      Introduced verify_master_password(): authenticates the user on every launch using 3 attempts max.
      Security alert if key.key exists but master.hash is deleted (blocks access to prevent intrusion).

  2. Encrypted Vault Storage
      Passwords are now encrypted with cryptography.Fernet before being saved to vault.json.
      key.key is generated once and used for all encryption/decryption.
      Encryption keys are stored securely and reused unless manually deleted.

  3. CRUD Operations for Vault Entries
      Add Entry: Stores website, username/email, and encrypted password.
      View Entries: Decrypts and displays all saved credentials.
      Edit Entry: Allows updating of username/email or password.
      Delete Entry: Removes an entry from the vault.
      Case-insensitive search: Find entries by website or username.

  4. Input Validation & UX Enhancements
      Added .strip() to remove accidental whitespace in input.
      Empty vault feedback: "Vault is empty."
      Pretty formatting for listing entries, passwords, and errors.
      Clean and user-friendly terminal prompts.

  5. Secure Design Decisions
      Enforced vault access denial if master.hash is missing but key.key exists (prevents unauthorized resets).
      Passwords stored in vault.json are no longer readable without the correct key and master password.
 --------------------------------------------------------------------------------------------------------------
Phase 1 Changelog
  1. Basic Password Vault System
      Implemented an initial password vault that allows users to:
      Data was stored in a local file named vault.json.

  2. Command-Line Menu
      Created a basic menu-driven interface.

  3. File Storage Mechanism
      Introduced basic load_vault() and save_vault() functions.

  4. Minimal Input Validation
      Trimmed extra spaces using .strip() during input collection.
      Basic checks were added for empty vault file.

  5. Clean Output Formatting
      Used clean terminal output to list entries.


    
