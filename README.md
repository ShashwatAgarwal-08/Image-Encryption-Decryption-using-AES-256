# Secure Image Encryptor

A secure image encryption and decryption tool with a modern GUI interface. This application uses AES-256-CBC encryption with PBKDF2 key derivation to securely encrypt image files while maintaining a user-friendly experience.

## Features

- Image encryption using AES-256 in CBC mode
- Secure password-based key derivation (PBKDF2-HMAC-SHA256)
- Modern GUI built with tkinter and ttk
- Support for multiple image formats (PNG, JPG, JPEG, BMP)
- Side-by-side image comparison
- Encryption strength analysis with visual metrics
- Comprehensive security metrics:
  - Entropy analysis
  - Histogram comparison
  - Correlation coefficient analysis
  - NPCR and UACI calculations

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd image_encryptor
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. The main window provides three options:
   - "Encrypt Image": Select an image to encrypt
   - "Decrypt Image": Select an encrypted file to decrypt
   - "Check Encryption Strength": Analyze the security of encrypted files

3. For encryption/decryption:
   - Select your input file
   - Enter a strong password
   - Choose where to save the output
   - Use the "Compare Images" button to view results

4. For security analysis:
   - Select both the original and encrypted files
   - View detailed metrics and visual analysis
   - Check the encryption strength verdict

## Security Features

- Strong encryption using AES-256-CBC
- Random IV generation for each encryption
- Secure key derivation with PBKDF2 (200,000 iterations)
- No plaintext password storage
- Proper padding using PKCS7
- Salt and IV prepended to encrypted files

## Screenshots

[TODO: Add screenshots of the application in use]
- Main window
- Encryption process
- Image comparison
- Security analysis results

## Requirements

- Python 3.7+
- pycryptodome
- Pillow
- matplotlib
- numpy

For a complete list of dependencies, see `requirements.txt`.

## Development

- `main.py`: Main application GUI and logic
- `crypto_utils.py`: Encryption/decryption functionality
- `analysis.py`: Security metrics and analysis
- `gui_components.py`: Reusable GUI widgets

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Specify your chosen license]

## Security Considerations

- Always use strong passwords
- Keep encrypted files and passwords secure
- The strength analyzer is for educational purposes
- No encryption is unbreakable with insufficient password strength