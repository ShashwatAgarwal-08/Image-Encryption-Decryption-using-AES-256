"""
Reusable GUI components for the image encryption application.
Includes custom styled buttons, frames, and dialog windows.
"""

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from typing import Callable, Optional, Tuple

class StyledButton(ttk.Button):
    """Custom styled button with consistent appearance."""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.style = ttk.Style()
        self.style.configure('Action.TButton',
                           padding=10,
                           font=('Helvetica', 10))
        self['style'] = 'Action.TButton'

class ImageDisplay(tk.Toplevel):
    """Window for displaying image comparisons side by side."""
    def __init__(self, master, original_path: str, processed_path: str,
                visualization_path: str = None, title: str = "Image Comparison",
                max_size: Tuple[int, int] = (300, 300)):
        super().__init__(master)
        self.title(title)
        self.max_size = max_size
        
        # Create main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Load and display images
        self._setup_images(original_path, processed_path, visualization_path)
        
    def _setup_images(self, original_path: str, processed_path: str, visualization_path: str = None):
        """Load, resize and display the images."""
        try:
            # Load images
            original = Image.open(original_path)
            processed = Image.open(processed_path)
            
            # Resize images while maintaining aspect ratio
            original_resized = self._resize_image(original)
            processed_resized = self._resize_image(processed)
            
            # Convert to PhotoImage
            original_photo = ImageTk.PhotoImage(original_resized)
            processed_photo = ImageTk.PhotoImage(processed_resized)
            
            # Keep references to prevent garbage collection
            self.original_photo = original_photo
            self.processed_photo = processed_photo
            
            # Number of columns depends on whether we have visualization
            num_columns = 3 if visualization_path else 2
            
            # Create and place labels
            ttk.Label(self, text="Original").grid(row=0, column=0, padx=5, pady=5)
            ttk.Label(self, text="Processed").grid(row=0, column=1, padx=5, pady=5)
            
            ttk.Label(self, image=original_photo).grid(row=1, column=0, padx=5, pady=5)
            ttk.Label(self, image=processed_photo).grid(row=1, column=1, padx=5, pady=5)
            
            # Add visualization if available
            if visualization_path:
                visual = Image.open(visualization_path)
                visual_resized = self._resize_image(visual)
                visual_photo = ImageTk.PhotoImage(visual_resized)
                self.visual_photo = visual_photo  # Keep reference
                
                ttk.Label(self, text="Visual Representation").grid(row=0, column=2, padx=5, pady=5)
                ttk.Label(self, image=visual_photo).grid(row=1, column=2, padx=5, pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load images: {str(e)}")
            self.destroy()
            
    def _resize_image(self, image: Image.Image) -> Image.Image:
        """Resize image while maintaining aspect ratio."""
        width, height = image.size
        max_width, max_height = self.max_size
        
        # Calculate aspect ratio
        aspect = width / height
        
        if width > max_width or height > max_height:
            if aspect > 1:
                new_width = max_width
                new_height = int(max_width / aspect)
            else:
                new_height = max_height
                new_width = int(max_height * aspect)
            
            return image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        return image

class AnalysisDisplay(tk.Toplevel):
    """Window for displaying encryption strength analysis results."""
    def __init__(self, master, results: dict, figure=None):
        super().__init__(master)
        self.title("Encryption Strength Analysis")
        
        # Create main frame with padding
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Display results in a table format
        self._create_results_table(main_frame, results)
        
        # Display histogram if provided
        if figure:
            self._add_histogram(figure)
            
    def _create_results_table(self, parent: ttk.Frame, results: dict):
        """Create a table displaying the analysis results."""
        # Headers
        headers = ['Metric', 'Value']
        for col, header in enumerate(headers):
            ttk.Label(parent, text=header, font=('Helvetica', 10, 'bold')).grid(
                row=0, column=col, padx=5, pady=5, sticky=tk.W)
        
        # Add entropy
        row = 1
        ttk.Label(parent, text="Entropy (bits/byte)").grid(
            row=row, column=0, padx=5, pady=2, sticky=tk.W)
        ttk.Label(parent, text=f"{results['entropy']:.4f}").grid(
            row=row, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Add correlations
        row += 1
        for direction, value in results['correlations'].items():
            ttk.Label(parent, text=f"Correlation ({direction})").grid(
                row=row, column=0, padx=5, pady=2, sticky=tk.W)
            ttk.Label(parent, text=f"{value:.4f}").grid(
                row=row, column=1, padx=5, pady=2, sticky=tk.W)
            row += 1
            
        # Add NPCR and UACI
        if 'npcr' in results:
            ttk.Label(parent, text="NPCR (%)").grid(
                row=row, column=0, padx=5, pady=2, sticky=tk.W)
            ttk.Label(parent, text=f"{results['npcr']:.2f}").grid(
                row=row, column=1, padx=5, pady=2, sticky=tk.W)
            row += 1
            
        if 'uaci' in results:
            ttk.Label(parent, text="UACI (%)").grid(
                row=row, column=0, padx=5, pady=2, sticky=tk.W)
            ttk.Label(parent, text=f"{results['uaci']:.2f}").grid(
                row=row, column=1, padx=5, pady=2, sticky=tk.W)
            row += 1
            
        # Add verdict with appropriate color
        verdict_frame = ttk.Frame(parent)
        verdict_frame.grid(row=row, column=0, columnspan=2, pady=10)
        
        verdict_colors = {
            'Strong': '#4CAF50',  # Green
            'Moderate': '#FFA500',  # Orange
            'Weak': '#FF0000'  # Red
        }
        
        verdict_label = ttk.Label(
            verdict_frame,
            text=f"Encryption Strength: {results['verdict']}",
            font=('Helvetica', 12, 'bold')
        )
        verdict_label.pack()
        
    def _add_histogram(self, figure):
        """Add histogram plot to the window."""
        canvas = FigureCanvasTkAgg(figure, master=self)
        canvas.draw()
        canvas.get_tk_widget().grid(row=1, column=0, pady=10)
        
class LoadingDialog(tk.Toplevel):
    """Modal dialog showing a loading message."""
    def __init__(self, master, message: str = "Processing..."):
        super().__init__(master)
        self.title("Please Wait")
        
        # Make the dialog modal
        self.transient(master)
        self.grab_set()
        
        # Remove window decorations
        self.overrideredirect(True)
        
        # Create and pack the message label
        ttk.Label(self, text=message, padding=20).pack()
        
        # Center the dialog
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')