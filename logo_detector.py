import cv2
import numpy as np
from PIL import Image
import os
import hashlib
from datetime import datetime

class LogoDetector:
    """Logo detection for brand verification"""
    
    def __init__(self):
        # Known brand logos (simplified for demonstration)
        self.brand_signatures = {
            'paypal': ['paypal', 'pp'],
            'amazon': ['amazon', 'amzn', 'a to z'],
            'google': ['google', 'gmail', 'drive'],
            'facebook': ['facebook', 'fb', 'meta'],
            'microsoft': ['microsoft', 'ms', 'windows'],
            'apple': ['apple', 'mac', 'ios'],
            'bank_of_america': ['bank of america', 'bofa'],
            'wells_fargo': ['wells fargo', 'wf']
        }
        
        # Suspicious logo patterns
        self.suspicious_patterns = [
            'pixelated', 'blurry', 'mismatched_colors', 'wrong_aspect_ratio'
        ]
    
    def detect(self, image_path):
        """Detect and analyze logos in image"""
        try:
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return self.get_error_result()
            
            # Extract text from image (for brand names)
            from PIL import Image as PILImage
            import pytesseract
            pil_img = PILImage.open(image_path)
            text = pytesseract.image_to_string(pil_img).lower()
            
            # Detect potential brands
            detected_brands = []
            for brand, keywords in self.brand_signatures.items():
                for keyword in keywords:
                    if keyword in text:
                        detected_brands.append(brand)
                        break
            
            # Analyze logo quality
            quality_issues = self.analyze_logo_quality(img)
            
            # Check for suspicious modifications
            suspicious_modifications = self.check_suspicious_modifications(img)
            
            # Determine if logo appears legitimate
            is_suspicious = len(detected_brands) == 0 and len(suspicious_modifications) > 0
            
            return {
                'detected_brands': list(set(detected_brands)),
                'quality_issues': quality_issues,
                'suspicious_modifications': suspicious_modifications,
                'is_suspicious': is_suspicious,
                'recommendation': self.get_recommendation(is_suspicious, detected_brands),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error detecting logo: {e}")
            return self.get_error_result()
    
    def analyze_logo_quality(self, img):
        """Analyze logo image quality"""
        issues = []
        
        # Check resolution
        height, width = img.shape[:2]
        if width < 100 or height < 100:
            issues.append('Low resolution logo - possible copy')
        
        # Check for blur
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        if laplacian_var < 100:
            issues.append('Blurry logo - poor quality')
        
        # Check for compression artifacts
        if len(img.shape) == 3:
            if np.std(img) < 20:
                issues.append('Compression artifacts detected')
        
        # Check color distribution
        if len(img.shape) == 3:
            hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
            saturation = np.mean(hsv[:,:,1])
            if saturation < 50:
                issues.append('Low color saturation - possible watermark')
        
        return issues
    
    def check_suspicious_modifications(self, img):
        """Check for suspicious modifications"""
        modifications = []
        
        # Check for inconsistent scaling (non-uniform aspect ratio)
        height, width = img.shape[:2]
        aspect_ratio = width / height
        if aspect_ratio < 0.5 or aspect_ratio > 2.0:
            modifications.append('Unusual aspect ratio - possibly stretched')
        
        # Check for border artifacts (sign of copy-paste)
        edges = cv2.Canny(img, 50, 150)
        border_edge_density = np.mean(edges[0:10, :]) + np.mean(edges[-10:, :])
        if border_edge_density > 50:
            modifications.append('Border artifacts detected - possible composite')
        
        # Check for color anomalies
        if len(img.shape) == 3:
            # Check for unusual color distributions
            colors = img.reshape(-1, 3)
            unique_colors = len(np.unique(colors, axis=0))
            if unique_colors > 1000 and unique_colors < 100:
                modifications.append('Unusual color palette - possible modification')
        
        return modifications
    
    def get_recommendation(self, is_suspicious, detected_brands):
        """Get recommendation based on detection"""
        if is_suspicious:
            return '⚠️ Suspicious logo detected. This may be an attempt to impersonate a legitimate brand.'
        elif detected_brands:
            return f'✓ Detected brand(s): {", ".join(detected_brands)}. Verify authenticity through official channels.'
        else:
            return 'ℹ️ No recognized brand logos detected. Verify the source independently.'
    
    def get_error_result(self):
        """Return error result"""
        return {
            'detected_brands': [],
            'quality_issues': ['Unable to analyze logo'],
            'suspicious_modifications': [],
            'is_suspicious': True,
            'recommendation': 'Unable to analyze logo. Exercise caution.',
            'timestamp': datetime.now().isoformat(),
            'error': True
        }
