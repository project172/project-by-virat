import cv2
import numpy as np
from PIL import Image
import pytesseract
import hashlib
from datetime import datetime
import os

class ImageAnalyzer:
    """Image analysis for phishing detection"""
    
    def __init__(self):
        self.suspicious_text_patterns = ['login', 'verify', 'account', 'password', 
                                          'credit card', 'ssn', 'security']
        
    def analyze(self, image_path):
        """Analyze image for phishing indicators"""
        try:
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return self.get_error_result()
            
            # Extract features
            features = self.extract_features(img)
            
            # Extract text using OCR
            text = self.extract_text(image_path)
            
            # Check for suspicious text
            suspicious_text = self.check_suspicious_text(text)
            
            # Check for QR codes
            qr_code = self.detect_qr_code(img)
            
            # Analyze image quality
            quality_issues = self.analyze_quality(img)
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(suspicious_text, qr_code, quality_issues)
            
            # Determine status
            if risk_score >= 70:
                status = 'danger'
                message = '⚠️ CRITICAL: Image contains suspicious content'
            elif risk_score >= 40:
                status = 'warning'
                message = '⚠️ WARNING: Image shows suspicious characteristics'
            else:
                status = 'safe'
                message = '✅ SAFE: Image appears legitimate'
            
            return {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'extracted_text': text[:500] if text else '',
                'suspicious_text': suspicious_text,
                'qr_code_detected': qr_code is not None,
                'quality_issues': quality_issues,
                'recommendation': self.get_recommendation(status),
                'timestamp': datetime.now().isoformat(),
                'analysis_type': 'image'
            }
            
        except Exception as e:
            print(f"Error analyzing image: {e}")
            return self.get_error_result()
    
    def extract_features(self, img):
        """Extract image features"""
        features = {}
        
        # Image dimensions
        height, width = img.shape[:2]
        features['width'] = width
        features['height'] = height
        features['aspect_ratio'] = width / height if height > 0 else 0
        
        # Color analysis
        features['is_grayscale'] = len(img.shape) == 2
        
        if len(img.shape) == 3:
            # Convert to HSV for better color analysis
            hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
            
            # Calculate color statistics
            features['mean_hue'] = np.mean(hsv[:,:,0])
            features['mean_saturation'] = np.mean(hsv[:,:,1])
            features['mean_value'] = np.mean(hsv[:,:,2])
        
        # Edge detection (indicates text vs graphics)
        edges = cv2.Canny(img, 100, 200)
        features['edge_density'] = np.sum(edges > 0) / (width * height)
        
        # Blur detection
        laplacian_var = cv2.Laplacian(img, cv2.CV_64F).var()
        features['is_blurry'] = laplacian_var < 100
        
        return features
    
    def extract_text(self, image_path):
        """Extract text from image using OCR"""
        try:
            # Open image with PIL
            img = Image.open(image_path)
            
            # Perform OCR
            text = pytesseract.image_to_string(img)
            return text.strip()
        except Exception as e:
            print(f"OCR error: {e}")
            return ""
    
    def check_suspicious_text(self, text):
        """Check for suspicious text patterns"""
        suspicious = []
        text_lower = text.lower()
        
        for pattern in self.suspicious_text_patterns:
            if pattern in text_lower:
                suspicious.append(pattern)
        
        return suspicious
    
    def detect_qr_code(self, img):
        """Detect QR codes in image"""
        try:
            qr_detector = cv2.QRCodeDetector()
            data, points, _ = qr_detector.detectAndDecode(img)
            
            if data:
                return {
                    'data': data[:100],  # Limit length
                    'points': len(points) if points is not None else 0
                }
            return None
        except:
            return None
    
    def analyze_quality(self, img):
        """Analyze image quality issues"""
        issues = []
        
        # Check resolution
        height, width = img.shape[:2]
        if width < 200 or height < 200:
            issues.append('Low resolution image')
        
        # Check for compression artifacts
        if len(img.shape) == 3:
            # Check for JPEG artifacts
            if np.std(img) < 30:
                issues.append('Possible compression artifacts')
        
        # Check for watermark
        # Simple detection of high contrast edges in corners
        corners = [
            img[0:50, 0:50],
            img[0:50, -50:],
            img[-50:, 0:50],
            img[-50:, -50:]
        ]
        
        for corner in corners:
            if len(corner.shape) == 3:
                corner_gray = cv2.cvtColor(corner, cv2.COLOR_BGR2GRAY)
            else:
                corner_gray = corner
            
            # Check for high edge density (potential watermark)
            edges = cv2.Canny(corner_gray, 50, 150)
            edge_density = np.sum(edges > 0) / (corner.shape[0] * corner.shape[1])
            
            if edge_density > 0.3:
                issues.append('Possible watermark detected')
                break
        
        return issues
    
    def calculate_risk_score(self, suspicious_text, qr_code, quality_issues):
        """Calculate overall risk score"""
        risk_score = 0
        
        # Suspicious text risk
        if suspicious_text:
            risk_score += min(len(suspicious_text) * 15, 50)
        
        # QR code risk (could redirect to malicious site)
        if qr_code:
            risk_score += 25
        
        # Quality issues risk
        if quality_issues:
            risk_score += min(len(quality_issues) * 10, 20)
        
        return min(risk_score, 100)
    
    def get_recommendation(self, status):
        """Get recommendation based on status"""
        if status == 'danger':
            return '🚫 Do not trust this image. It contains suspicious content that may be part of a phishing attempt.'
        elif status == 'warning':
            return '⚠️ Be cautious. This image shows suspicious characteristics. Verify the source before proceeding.'
        else:
            return '✓ Image appears safe, but always verify the context and source.'
    
    def get_error_result(self):
        """Return error result"""
        return {
            'risk_score': 100,
            'status': 'danger',
            'message': '⚠️ ERROR: Unable to analyze image',
            'extracted_text': '',
            'suspicious_text': [],
            'qr_code_detected': False,
            'quality_issues': ['Image analysis failed'],
            'recommendation': 'Do not trust this image as it could not be properly analyzed.',
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'image_error'
        }
