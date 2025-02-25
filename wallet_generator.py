import tkinter as tk
from tkinter import messagebox, filedialog
from eth_account import Account
from mnemonics import Mnemonic
import secrets
from bitcoinlib.keys import Key
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import hashlib

class CryptoWalletGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Wallet Generator")
        self.root.geometry("600x400")

        # Blockchain selection
        tk.Label(root, text="Select Blockchain:").pack(pady=5)
        self.blockchain_var = tk.StringVar(value="Ethereum")
        tk.Radiobutton(root, text="Ethereum", variable=self.blockchain_var, value="Ethereum").pack()
        tk.Radiobutton(root, text="Bitcoin", variable=self.blockchain_var, value="Bitcoin").pack()

        # Buttons
        tk.Button(root, text="Generate Wallet", command=self.generate_wallet).pack(pady=5)
        tk.Button(root, text="Save to Encrypted File", command=self.save_to_file).pack(pady=5)
        tk.Button(root, text="Load and Decrypt File", command=self.load_and_decrypt).pack(pady=5)

        # Output text area
        self.output_text = tk.Text(root, height=15, width=70)
        self.output_text.pack(pady=10)

        # Wallet data
        self.wallet_data = ""

    def generate_wallet(self):
        blockchain = self.blockchain_var.get()
        self.output_text.delete(1.0, tk.END)  # Clear previous output

        if blockchain == "Ethereum":
            private_key = "0x" + secrets.token_hex(32)
            account = Account.from_key(private_key)
            mnemo = Mnemonic("english")
            seed_phrase = mnemo.generate(strength=128)

            self.wallet_data = (
                f"=== Ethereum Wallet Generated ===\n"
                f"Private Key: {private_key}\n"
                f"Public Key: {account._key_obj.public_key}\n"
                f"Ethereum Address: {account.address}\n"
                f"Seed Phrase (Mnemonic): {seed_phrase}\n"
                f"\n⚠️ WARNING: Store your private key and seed phrase securely!"
            )

        elif blockchain == "Bitcoin":
            key = Key(network='bitcoin')
            private_key = key.secret_hex()
            address = key.address()
            seed_phrase = key.mnemonic()

            self.wallet_data = (
                f"=== Bitcoin Wallet Generated ===\n"
                f"Private Key: {private_key}\n"
                f"Bitcoin Address: {address}\n"
                f"Seed Phrase (Mnemonic): {seed_phrase}\n"
                f"\n⚠️ WARNING: Store your private key and seed phrase securely!"
            )

        self.output_text.insert(tk.END, self.wallet_data)

    def save_to_file(self):
        if not self.wallet_data:
            messagebox.showwarning("No Data", "Generate a wallet first!")
            return

        password = tk.simpledialog.askstring("Password", "Enter a password for encryption:", show="*")
        if not password:
            messagebox.showwarning("No Password", "Password is required to encrypt the file!")
            return

        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(self.wallet_data.encode())

        file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
            messagebox.showinfo("Success", f"Wallet saved to {file_path}")

    def load_and_decrypt(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if not file_path:
            return

        password = tk.simpledialog.askstring("Password", "Enter the password to decrypt:", show="*")
        if not password:
            messagebox.showwarning("No Password", "Password is required to decrypt the file!")
            return

        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            kdf = PBKDF2HMAC(
                algorithm=hashlib.sha256(),
                length=32,
                salt=encrypted_data[:16],  # Assuming salt is prepended; adjust if saved differently
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_data[16:]).decode()  # Skip salt bytes

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, decrypted_data)
            self.wallet_data = decrypted_data
            messagebox.showinfo("Success", "File decrypted successfully!")

        except InvalidToken:
            messagebox.showerror("Error", "Invalid password or corrupted file!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoWalletGenerator(root)
    root.mainloop()