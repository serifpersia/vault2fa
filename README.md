# Vault2FA

![image](https://github.com/user-attachments/assets/bb38ad77-c0a8-4ae7-ab1a-729c078cdf81)

A secure, local-first, web-based two-factor authenticator application.

## Features

- **Encryption:**
- **Account Management:** Easily add, edit, and delete accounts.
- **Bulk Import:** Supports importing accounts from a decrypted Bitwarden JSON export.

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v16 or later is recommended)
- npm (comes with Node.js)

### Installation & Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/serifpersia/vault2fa.git
    cd vault2fa
    ```

2.  **Install dependencies:**
    This project has a simple Node.js/Express backend to serve the files.
    ```bash
    npm install
    ```

3.  **Run the server:**
    ```bash
    node server.js
    ```

4.  **Open the application:**
    Open your web browser and navigate to `http://localhost:3000`.

##  vault2fa Usage

1.  **Create a Vault:** On your first visit, you will be prompted to create a master password. This password is the only way to access your vault. **Do not forget it!**
2.  **Unlock:** On subsequent visits, enter your master password to decrypt and unlock your vault.
3.  **Add Accounts:**
    - Click the `+` button to open the menu.
    - **Manual Entry:** Provide an account name and the Base32 secret key from your service provider.
    - **Import:** Select a decrypted Bitwarden JSON file to bulk-import your existing 2FA accounts.
4.  **Manage Accounts:**
    - Click the `...` button on any account card to edit its name or delete it.
    - **Important:** Before deleting an account, ensure you have disabled 2FA on the corresponding website first to avoid being locked out.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
