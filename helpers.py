import hashlib
import re
import os
import json
import logging
from datetime import datetime
from functools import wraps
import secrets
import string

class SecurityUtils:
    """Security utilities for the application"""
    
    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        if not url:
            return False
        
        # Basic URL validation
        url_pattern = re.compile(
            r'^(http|https)://'  # http:// or https://
            r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'  # domain
            r'(:\d+)?'  # optional port
            r'(/[-a-zA-Z0-9@:%._\+~#=]*)*'  # path
            r'(\?[;&a-zA-Z0-9%_\-\.~+&=]*)?'  # query string
            r'(#[-a-zA-Z0-9_]*)?$',  # fragment
            re.IGNORECASE
        )
        
        return bool(url_pattern.match(url))
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        if not email:
            return False
        
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        return bool(email_pattern.match(email))
    
    @staticmethod
    def validate_file_type(filename):
        """Validate file type for uploads"""
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
        ext = os.path.splitext(filename)[1].lower()
        return ext in allowed_extensions
    
    @staticmethod
    def sanitize_input(text):
        """Sanitize user input to prevent injection"""
        if not text:
            return ""
        
        # Remove dangerous characters
        text = re.sub(r'[<>{}]', '', text)
        
        # Escape HTML entities
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        
        return text
    
    @staticmethod
    def generate_token(length=32):
        """Generate secure random token"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def hash_data(data):
        """Generate hash for data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def mask_sensitive_data(text, pattern=r'\b\d{16}\b'):
        """Mask sensitive data in text"""
        return re.sub(pattern, '****', text)

class Logger:
    """Custom logging utility"""
    
    def __init__(self, log_file='phishshield.log'):
        self.log_file = log_file
        self.setup_logging()
        self.analysis_count = 0
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('PhishShield')
    
    def log_info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def log_error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def log_warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def log_analysis(self, analysis_type, result):
        """Log analysis results"""
        self.analysis_count += 1
        self.log_info(f"Analysis #{self.analysis_count}: {analysis_type} - Risk: {result.get('risk_score', 'N/A')}")
        
        # Save to JSON log file
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': analysis_type,
            'result': result,
            'analysis_id': self.analysis_count
        }
        
        try:
            with open('analysis_log.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
    
    def get_analysis_count(self):
        """Get total analysis count"""
        return self.analysis_count

class DataValidator:
    """Data validation utilities"""
    
    @staticmethod
    def validate_url_analysis_data(data):
        """Validate URL analysis request data"""
        if not data:
            return False, "No data provided"
        
        url = data.get('url', '')
        if not url:
            return False, "No URL provided"
        
        if not SecurityUtils.validate_url(url):
            return False, "Invalid URL format"
        
        return True, "Valid"
    
    @staticmethod
    def validate_email_analysis_data(data):
        """Validate email analysis request data"""
        if not data:
            return False, "No data provided"
        
        content = data.get('content', '')
        if not content:
            return False, "No email content provided"
        
        return True, "Valid"
    
    @staticmethod
    def validate_text_analysis_data(data):
        """Validate text analysis request data"""
        if not data:
            return False, "No data provided"
        
        text = data.get('text', '')
        if not text:
            return False, "No text provided"
        
        if len(text) > 10000:
            return False, "Text too long (max 10000 characters)"
        
        return True, "Valid"

class ResponseFormatter:
    """Format API responses"""
    
    @staticmethod
    def success_response(data, message="Success"):
        """Format success response"""
        return {
            'success': True,
            'message': message,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
    
    @staticmethod
    def error_response(message, code=400):
        """Format error response"""
        return {
            'success': False,
            'error': message,
            'code': code,
            'timestamp': datetime.now().isoformat()
        }, code
    
    @staticmethod
    def format_analysis_result(result):
        """Format analysis result for consistent output"""
        return {
            'success': True,
            'analysis': result,
            'metadata': {
                'timestamp': result.get('timestamp', datetime.now().isoformat()),
                'version': '2.0.0'
            }
        }
