"""
Image encryption analysis module for computing various security metrics.
Includes entropy calculation, histogram analysis, and correlation coefficients.
"""

import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from typing import Tuple, Dict, List, Union
import io

class AnalysisError(Exception):
    """Custom exception for analysis operations."""
    pass

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of the data in bits per byte.
    
    Args:
        data: Bytes to analyze
        
    Returns:
        Entropy value (0-8 bits per byte)
    """
    try:
        # Calculate frequency of each byte value
        freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        prob = freq / len(data)
        
        # Remove zero probabilities to avoid log(0)
        prob = prob[prob > 0]
        
        # Calculate entropy
        entropy = -np.sum(prob * np.log2(prob))
        return entropy
        
    except Exception as e:
        raise AnalysisError(f"Entropy calculation failed: {str(e)}")

def calculate_correlation(image: np.ndarray) -> Dict[str, float]:
    """
    Calculate correlation coefficients in horizontal, vertical, and diagonal directions.
    
    Args:
        image: Image array (grayscale)
        
    Returns:
        Dictionary with correlation values for each direction
    """
    try:
        def calculate_direction_correlation(x: np.ndarray, y: np.ndarray) -> float:
            """Calculate correlation coefficient between two arrays."""
            return np.corrcoef(x.flatten(), y.flatten())[0, 1]
        
        # Ensure image is 2D (grayscale)
        if len(image.shape) > 2:
            image = image.mean(axis=2)  # Convert to grayscale
            
        h, w = image.shape
        correlations = {}
        
        # Horizontal correlation
        correlations['horizontal'] = calculate_direction_correlation(
            image[:, :-1], image[:, 1:]
        )
        
        # Vertical correlation
        correlations['vertical'] = calculate_direction_correlation(
            image[:-1, :], image[1:, :]
        )
        
        # Diagonal correlation
        correlations['diagonal'] = calculate_direction_correlation(
            image[:-1, :-1], image[1:, 1:]
        )
        
        return correlations
        
    except Exception as e:
        raise AnalysisError(f"Correlation calculation failed: {str(e)}")

def calculate_npcr_uaci(original: np.ndarray, encrypted: np.ndarray) -> Dict[str, float]:
    """
    Calculate NPCR (Number of Pixels Change Rate) and UACI (Unified Average Changing Intensity).
    
    Args:
        original: Original image array
        encrypted: Encrypted image array
        
    Returns:
        Dictionary with NPCR and UACI values
    """
    try:
        if original.shape != encrypted.shape:
            raise AnalysisError("Images must have the same dimensions")
            
        # Calculate NPCR
        diff_array = (original != encrypted).astype(np.float32)
        npcr = 100.0 * np.sum(diff_array) / diff_array.size
        
        # Calculate UACI
        uaci = 100.0 * np.sum(np.abs(original.astype(np.float32) - encrypted.astype(np.float32))) / (255.0 * diff_array.size)
        
        return {
            'npcr': npcr,
            'uaci': uaci
        }
        
    except Exception as e:
        raise AnalysisError(f"NPCR/UACI calculation failed: {str(e)}")

def generate_histogram_figure(image_data: bytes, encrypted_data: bytes) -> Figure:
    """
    Generate histogram comparison figure for original and encrypted data.
    
    Args:
        image_data: Original image bytes
        encrypted_data: Encrypted image bytes
        
    Returns:
        Matplotlib Figure object
    """
    try:
        # Create histograms
        fig = Figure(figsize=(10, 4))
        
        # Original histogram
        ax1 = fig.add_subplot(121)
        orig_hist = np.bincount(np.frombuffer(image_data, dtype=np.uint8), minlength=256)
        ax1.bar(range(256), orig_hist, color='blue', alpha=0.7)
        ax1.set_title('Original Image Histogram')
        ax1.set_xlabel('Pixel Value')
        ax1.set_ylabel('Frequency')
        
        # Encrypted histogram
        ax2 = fig.add_subplot(122)
        enc_hist = np.bincount(np.frombuffer(encrypted_data, dtype=np.uint8), minlength=256)
        ax2.bar(range(256), enc_hist, color='red', alpha=0.7)
        ax2.set_title('Encrypted Image Histogram')
        ax2.set_xlabel('Pixel Value')
        ax2.set_ylabel('Frequency')
        
        fig.tight_layout()
        return fig
        
    except Exception as e:
        raise AnalysisError(f"Histogram generation failed: {str(e)}")

def analyze_encryption_strength(original_data: bytes, encrypted_data: bytes) -> Dict[str, Union[float, str]]:
    """
    Analyze encryption strength using various metrics.
    
    Args:
        original_data: Original image bytes
        encrypted_data: Encrypted image bytes
        
    Returns:
        Dictionary containing analysis results and strength verdict
    """
    try:
        results = {}
        
        # Calculate entropy
        results['entropy'] = calculate_entropy(encrypted_data)
        
        # Convert bytes to numpy arrays for correlation analysis
        orig_array = np.frombuffer(original_data, dtype=np.uint8).reshape(-1, 1)
        enc_array = np.frombuffer(encrypted_data, dtype=np.uint8).reshape(-1, 1)
        
        # Calculate correlations
        results['correlations'] = calculate_correlation(enc_array)
        
        # Calculate NPCR and UACI
        metrics = calculate_npcr_uaci(orig_array, enc_array)
        results.update(metrics)
        
        # Determine strength verdict
        strength_score = 0
        
        # Entropy check (ideal is close to 8.0)
        if results['entropy'] > 7.9:
            strength_score += 2
        elif results['entropy'] > 7.5:
            strength_score += 1
            
        # Correlation check (ideal is close to 0)
        avg_correlation = np.mean([abs(v) for v in results['correlations'].values()])
        if avg_correlation < 0.1:
            strength_score += 2
        elif avg_correlation < 0.3:
            strength_score += 1
            
        # NPCR check (ideal is close to 100%)
        if results['npcr'] > 99:
            strength_score += 2
        elif results['npcr'] > 90:
            strength_score += 1
            
        # Set verdict based on score
        if strength_score >= 5:
            results['verdict'] = 'Strong'
        elif strength_score >= 3:
            results['verdict'] = 'Moderate'
        else:
            results['verdict'] = 'Weak'
            
        return results
        
    except Exception as e:
        raise AnalysisError(f"Encryption strength analysis failed: {str(e)}")