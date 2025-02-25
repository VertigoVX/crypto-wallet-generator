# Crypto Wallet Generator

A Python-based tool to generate and manage cryptocurrency wallets for Ethereum and Bitcoin, featuring a GUI, encryption, and decryption capabilities.

---

## Features
- **Wallet Generation**: Create wallets for Ethereum (private key, public key, address, mnemonic) and Bitcoin (private key, address, mnemonic).
- **GUI Interface**: Built with `tkinter` for easy interaction.
- **Encryption**: Save wallet data to an encrypted `.enc` file using a user-provided password.
- **Decryption**: Load and decrypt saved wallet files with the correct password.
- **Cross-Blockchain Support**: Supports both Ethereum and Bitcoin key generation.

---

## Prerequisites
Install the required Python libraries:
```bash
pip install eth-account mnemonics bitcoinlib cryptography
```

## How to Run
Clone this repository:
```bash
git clone <your-repo-url>
cd <repo-name>
```
Run the script:
```bash
python wallet_generator.py
```
Use the GUI:
- Select a blockchain (Ethereum or Bitcoin).
- Click "Generate Wallet" to create a new wallet.
- Click "Save to Encrypted File" to save with a password.
- Click "Load and Decrypt File" to open a saved .enc file.

## Security Notes
- Private Keys & Seed Phrases: Store them securely and never share them.
- Encryption: Uses Fernet (symmetric encryption) with a PBKDF2-derived key. For production use, consider additional security measures (e.g., separate salt storage).
- Test Environment: Generated keys are for demo purposes; use real wallets for actual crypto transactions.

## Future Enhancements
Add QR code generation for addresses.
Support more blockchains (e.g., Solana, Cardano).

## License
This project is open-source under the MIT License.
