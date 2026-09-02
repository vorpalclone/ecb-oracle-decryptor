# ecb-oracle-decryptor
A Python automation script to execute a Byte-at-a-time AES-ECB decryption attack to recover hidden plaintext messages from a vulnerable oracle interface.

## Features
- **Block Size Calculation:** Automatically detects the cipher block size.
- **Offset Detection:** Determines the preamble length before the user payload.
- **Automated Decryption:** Recovers the full plaintext message using a byte-at-a-time brute force approach.

## Dependencies
Ensure you have the required Python packages installed:
```bash
pip install pycryptodome beautifulsoup4 requests
