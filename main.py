"""
Main application module for the Secure Image Encryptor.
Implements the GUI and coordinates the encryption/decryption operations.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from PIL import Image
import threading
from typing import Optional, Tuple

from crypto_utils import (encrypt_image, decrypt_image, combine_encrypted_data, 
                      split_encrypted_data, create_visualization_image, CryptoError)
from analysis import analyze_encryption_strength, generate_histogram_figure, AnalysisError
from gui_components import StyledButton, ImageDisplay, AnalysisDisplay, LoadingDialog

class SecureImageEncryptor(tk.Tk):
    """Main application window for the Secure Image Encryptor."""
    
    def __init__(self):
        super().__init__()
        
        self.title("Secure Image Encryptor")
        self.geometry("600x400")
        self._setup_ui()
        
        # Store paths for image comparison
        self.original_image_path = None
        self.processed_image_path = None
        
    def _setup_ui(self):
        """Set up the user interface components."""
        # Main frame with padding
        main_frame = ttk.Frame(self, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Secure Image Encryptor",
            font=('Helvetica', 16, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=1, column=0, columnspan=2, pady=20)
        
        # Encrypt button
        self.encrypt_btn = StyledButton(
            buttons_frame,
            text="Encrypt Image",
            command=self._encrypt_image
        )
        self.encrypt_btn.grid(row=0, column=0, padx=10)
        
        # Decrypt button
        self.decrypt_btn = StyledButton(
            buttons_frame,
            text="Decrypt Image",
            command=self._decrypt_image
        )
        self.decrypt_btn.grid(row=0, column=1, padx=10)
        
        # Analysis button
        self.analysis_btn = StyledButton(
            main_frame,
            text="Check Encryption Strength",
            command=self._analyze_encryption
        )
        self.analysis_btn.grid(row=2, column=0, columnspan=2, pady=20)
        
        # Compare button (hidden initially)
        self.compare_btn = StyledButton(
            main_frame,
            text="Compare Images",
            command=self._show_comparison
        )
        self.compare_btn.grid(row=3, column=0, columnspan=2, pady=20)
        self.compare_btn.grid_remove()  # Hide initially
        
    def _get_image_file(self, mode: str) -> Optional[str]:
        """Open file dialog for selecting an image file."""
        file_types = [
            ('Image files', '*.png;*.jpg;*.jpeg;*.bmp'),
            ('All files', '*.*')
        ]
        
        if mode == 'encrypt':
            return filedialog.askopenfilename(
                title="Select Image to Encrypt",
                filetypes=file_types
            )
        else:  # decrypt
            return filedialog.askopenfilename(
                title="Select Encrypted File",
                filetypes=[('Encrypted files', '*.enc'), ('All files', '*.*')]
            )
            
    def _get_save_path(self, mode: str, original_path: str) -> Optional[str]:
        """Open file dialog for saving the processed image."""
        base_name = os.path.splitext(os.path.basename(original_path))[0]
        
        if mode == 'encrypt':
            return filedialog.asksaveasfilename(
                title="Save Encrypted File",
                defaultextension='.enc',
                initialfile=f"{base_name}_encrypted.enc",
                filetypes=[('Encrypted files', '*.enc')]
            )
        else:  # decrypt
            return filedialog.asksaveasfilename(
                title="Save Decrypted Image",
                defaultextension='.png',
                initialfile=f"{base_name}_decrypted.png",
                filetypes=[('PNG files', '*.png'), ('All files', '*.*')]
            )
            
    def _get_password(self) -> Optional[str]:
        """Prompt user for password."""
        return simpledialog.askstring(
            "Enter Password",
            "Enter encryption/decryption password:",
            show='*'
        )
        
    def _process_image(self, mode: str):
        """Process (encrypt/decrypt) the selected image."""
        try:
            # Get input file
            input_path = self._get_image_file(mode)
            if not input_path:
                return
                
            # Get password
            password = self._get_password()
            if not password:
                return
                
            # Get save path
            save_path = self._get_save_path(mode, input_path)
            if not save_path:
                return
                
            # Show loading dialog
            loading = LoadingDialog(self)
            self.update()
            
            try:
                if mode == 'encrypt':
                    # Read image file
                    with open(input_path, 'rb') as f:
                        image_data = f.read()
                        
                    # Get original image size for visualization
                    with Image.open(input_path) as img:
                        original_size = img.size
                    
                    # Encrypt
                    salt, iv, encrypted_data = encrypt_image(image_data, password)
                    combined_data = combine_encrypted_data(salt, iv, encrypted_data)
                    
                    # Save encrypted file
                    with open(save_path, 'wb') as f:
                        f.write(combined_data)
                    
                    # Create and save visualization image
                    visual_path = os.path.splitext(save_path)[0] + '_visual.png'
                    visual_img = create_visualization_image(encrypted_data, original_size)
                    visual_img.save(visual_path)
                    
                    # Store path for visualization image
                    self.visual_image_path = visual_path
                    
                else:  # decrypt
                    # Read encrypted file
                    with open(input_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    # Split data and decrypt
                    salt, iv, ciphertext = split_encrypted_data(encrypted_data)
                    decrypted_data = decrypt_image(ciphertext, salt, iv, password)
                    
                    try:
                        # Verify the decrypted data is a valid image
                        from io import BytesIO
                        img = Image.open(BytesIO(decrypted_data))
                        img.verify()  # Verify it's a valid image
                        
                        # Save decrypted image
                        img = Image.open(BytesIO(decrypted_data))  # Need to reopen after verify
                        img.save(save_path)
                    except Exception as e:
                        raise CryptoError(f"Invalid image data or incorrect password: {str(e)}")
                        
                    # Create visualization of encrypted data for comparison
                    visual_path = os.path.splitext(input_path)[0] + '_visual.png'
                    if not os.path.exists(visual_path):
                        visual_img = create_visualization_image(ciphertext)
                        visual_img.save(visual_path)
                        
                # Store paths for comparison
                if mode == 'encrypt':
                    # For encryption: original -> visual
                    self.original_image_path = input_path
                    self.processed_image_path = visual_path
                else:
                    # For decryption: visual -> decrypted
                    self.original_image_path = visual_path
                    self.processed_image_path = save_path
                
                # Show compare button
                self.compare_btn.grid()
                
                messagebox.showinfo(
                    "Success",
                    f"Image successfully {'encrypted' if mode == 'encrypt' else 'decrypted'} and saved!"
                )
                
            finally:
                loading.destroy()
                
        except CryptoError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
            
    def _encrypt_image(self):
        """Handle encryption button click."""
        self._process_image('encrypt')
        
    def _decrypt_image(self):
        """Handle decryption button click."""
        self._process_image('decrypt')
        
    def _show_comparison(self):
        """Show image comparison window."""
        if self.original_image_path and self.processed_image_path:
            title = "Image Comparison"
            # Just show two images side by side
            ImageDisplay(self, 
                       self.original_image_path, 
                       self.processed_image_path,
                       None,  # No third image needed
                       title)
            
    def _analyze_encryption(self):
        """Analyze encryption strength of a selected encrypted file."""
        try:
            # Get original and encrypted files
            original_path = filedialog.askopenfilename(
                title="Select Original Image",
                filetypes=[('Image files', '*.png;*.jpg;*.jpeg;*.bmp')]
            )
            if not original_path:
                return
                
            encrypted_path = filedialog.askopenfilename(
                title="Select Encrypted File",
                filetypes=[('Encrypted files', '*.enc')]
            )
            if not encrypted_path:
                return
                
            # Show loading dialog
            loading = LoadingDialog(self, "Analyzing encryption strength...")
            self.update()
            
            try:
                # Read files
                with open(original_path, 'rb') as f:
                    original_data = f.read()
                with open(encrypted_path, 'rb') as f:
                    encrypted_data = f.read()
                    
                # Skip salt and IV in encrypted data
                _, _, encrypted_data = split_encrypted_data(encrypted_data)
                
                # Analyze
                results = analyze_encryption_strength(original_data, encrypted_data)
                
                # Generate histogram
                histogram = generate_histogram_figure(original_data, encrypted_data)
                
                # Show results
                AnalysisDisplay(self, results, histogram)
                
            finally:
                loading.destroy()
                
        except AnalysisError as e:
            messagebox.showerror("Analysis Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")

def main():
    """Main entry point of the application."""
    app = SecureImageEncryptor()
    app.mainloop()

if __name__ == '__main__':
    main()