import re
import tldextract
from urllib.parse import urlparse
import whois
from datetime import datetime
import requests
import socket
import ssl
import hashlib

class URLAnalyzer:
    """Advanced URL analysis for phishing detection"""
    
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', 
                                 '.work', '.click', '.download', '.gq', '.ml', '.bid', 
                                 '.webcam', '.science', '.party', '.date', '.space']
        
        self.suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 
                                     'banking', 'paypal', 'password', 'update', 'confirm', 
                                     'authenticate', 'verify-account', 'security-update',
                                     'user', 'admin', 'support', 'helpdesk', 'unlock']
        
        self.suspicious_patterns = ['-secure', '-login', '-verify', 'account-update', 
                                     'security-check', 'secure-login', 'webscr', 'cmd=_login']
        
        self.brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple', 
                       'bank', 'wellsfargo', 'chase', 'citibank', 'americanexpress',
                       'ebay', 'walmart', 'bestbuy', 'target', 'netflix']
    
    def analyze(self, url):
        """Main analysis function"""
        features = self.extract_features(url)
        risk_score = self.calculate_risk_score(features)
        threats = self.identify_threats(features, url)
        status = self.determine_status(risk_score)
        
        return {
            'url': url,
            'risk_score': risk_score,
            'status': status,
            'message': self.get_status_message(status, risk_score),
            'recommendation': self.get_recommendation(status),
            'threats': threats,
            'features': features,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'url'
        }
    
    def extract_features(self, url):
        """Extract comprehensive features from URL"""
        features = {}
        
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            # Basic URL features
            features['url_length'] = len(url)
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_slashes'] = url.count('/')
            features['num_questions'] = url.count('?')
            features['num_equal'] = url.count('=')
            features['num_at'] = url.count('@')
            features['num_and'] = url.count('&')
            
            # Protocol features
            features['has_https'] = parsed.scheme == 'https'
            features['has_http'] = parsed.scheme == 'http'
            
            # Domain features
            features['domain_length'] = len(ext.domain)
            features['subdomain_length'] = len(ext.subdomain)
            features['suffix_length'] = len(ext.suffix)
            features['has_ip'] = bool(re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url))
            features['num_subdomains'] = ext.subdomain.count('.') + 1 if ext.subdomain else 0
            
            # Port features
            features['has_port'] = ':' in parsed.netloc and parsed.port is not None
            if features['has_port']:
                features['port_number'] = parsed.port
            
            # Path features
            features['path_length'] = len(parsed.path)
            features['num_path_segments'] = len([s for s in parsed.path.split('/') if s])
            
            # Query features
            features['has_query'] = bool(parsed.query)
            features['query_length'] = len(parsed.query)
            
            # Fragment features
            features['has_fragment'] = bool(parsed.fragment)
            
            # Character features
            features['has_hex_chars'] = bool(re.search(r'%[0-9a-fA-F]{2}', url))
            features['has_special_chars'] = bool(re.search(r'[^a-zA-Z0-9/:.-]', url))
            
            # Suspicious patterns
            features['has_suspicious_tld'] = any(ext.suffix.endswith(tld) for tld in self.suspicious_tlds)
            features['has_suspicious_keyword'] = any(keyword in url.lower() for keyword in self.suspicious_keywords)
            features['has_suspicious_pattern'] = any(pattern in url.lower() for pattern in self.suspicious_patterns)
            features['has_brand_name'] = any(brand in url.lower() for brand in self.brands)
            
            # Brand impersonation
            features['brand_impersonation'] = self.check_brand_impersonation(url, ext)
            
            # Check URL redirection
            features['has_redirection'] = '//' in url[url.find('://')+3:] if '://' in url else False
            
            # Check for encoded characters
            features['has_encoded_chars'] = bool(re.search(r'%[0-9a-fA-F]{2}', url))
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            features = self.get_default_features()
        
        return features
    
    def check_brand_impersonation(self, url, ext):
        """Check if URL is impersonating a legitimate brand"""
        url_lower = url.lower()
        
        for brand in self.brands:
            if brand in url_lower:
                # Check if it's the official domain
                if f".{brand}." not in url_lower and f"/{brand}" not in url_lower:
                    if brand != ext.domain.lower():
                        return True
        return False
    
    def calculate_risk_score(self, features):
        """Calculate risk score based on extracted features"""
        risk_score = 0
        
        # URL length risk
        if features['url_length'] > 100:
            risk_score += 10
        if features['url_length'] > 150:
            risk_score += 5
        
        # Protocol risk
        if not features['has_https']:
            risk_score += 25
        
        # IP address risk
        if features['has_ip']:
            risk_score += 35
        
        # Suspicious TLD risk
        if features['has_suspicious_tld']:
            risk_score += 30
        
        # Suspicious keywords risk
        if features['has_suspicious_keyword']:
            risk_score += 20
        
        # Suspicious patterns risk
        if features['has_suspicious_pattern']:
            risk_score += 25
        
        # Brand impersonation risk
        if features.get('brand_impersonation', False):
            risk_score += 25
        
        # Multiple subdomains risk
        if features['num_subdomains'] > 3:
            risk_score += 15
        
        # Special characters risk
        if features['has_special_chars']:
            risk_score += 10
        
        # Port usage risk
        if features['has_port']:
            port = features.get('port_number', 0)
            if port and port != 443 and port != 80:
                risk_score += 15
        
        # Redirection risk
        if features['has_redirection']:
            risk_score += 10
        
        # Encoded characters risk
        if features['has_encoded_chars']:
            risk_score += 10
        
        # At symbol risk
        if features['num_at'] > 0:
            risk_score += 15
        
        # Cap risk score at 100
        return min(risk_score, 100)
    
    def identify_threats(self, features, url):
        """Identify specific threats"""
        threats = []
        
        if features['has_ip']:
            threats.append('IP address detected instead of domain name (common phishing technique)')
        
        if not features['has_https']:
            threats.append('Missing HTTPS encryption - data transmission is insecure')
        
        if features['has_suspicious_tld']:
            threats.append('Suspicious top-level domain detected')
        
        if features['has_suspicious_keyword']:
            threats.append('Suspicious keywords detected in URL')
        
        if features['has_suspicious_pattern']:
            threats.append('Suspicious URL pattern detected')
        
        if features.get('brand_impersonation', False):
            threats.append('Potential brand impersonation detected')
        
        if features['num_subdomains'] > 3:
            threats.append('Excessive subdomains detected - attempt to appear legitimate')
        
        if features['url_length'] > 100:
            threats.append('Unusually long URL - often used to hide malicious intent')
        
        if features['has_port'] and features.get('port_number') not in [443, 80]:
            threats.append('Non-standard port usage - potential security risk')
        
        if features['has_redirection']:
            threats.append('URL redirection detected - could lead to malicious sites')
        
        if features['num_at'] > 0:
            threats.append('@ symbol in URL - can be used to bypass authentication checks')
        
        return threats
    
    def determine_status(self, risk_score):
        """Determine risk status based on score"""
        if risk_score >= 70:
            return 'danger'
        elif risk_score >= 40:
            return 'warning'
        else:
            return 'safe'
    
    def get_status_message(self, status, risk_score):
        """Get descriptive status message"""
        if status == 'danger':
            return f'⚠️ CRITICAL: This website appears to be a PHISHING site! Risk score: {risk_score}/100'
        elif status == 'warning':
            return f'⚠️ WARNING: This website shows suspicious characteristics. Risk score: {risk_score}/100'
        else:
            return f'✅ SAFE: This website appears legitimate. Risk score: {risk_score}/100'
    
    def get_recommendation(self, status):
        """Get safety recommendation"""
        if status == 'danger':
            return '🚫 DO NOT PROCEED! This site is highly likely to steal your credentials. Close immediately.'
        elif status == 'warning':
            return '🔍 Proceed with extreme caution. Verify URL carefully and avoid entering sensitive information.'
        else:
            return '✓ You can proceed, but always remain vigilant and verify website authenticity.'
    
    def get_default_features(self):
        """Return default features in case of error"""
        return {
            'url_length': 0, 'num_dots': 0, 'num_hyphens': 0, 'num_slashes': 0,
            'num_questions': 0, 'num_equal': 0, 'num_at': 0, 'num_and': 0,
            'has_https': False, 'has_http': False, 'domain_length': 0, 'subdomain_length': 0,
            'suffix_length': 0, 'has_ip': False, 'num_subdomains': 0, 'has_port': False,
            'path_length': 0, 'num_path_segments': 0, 'has_query': False, 'query_length': 0,
            'has_fragment': False, 'has_hex_chars': False, 'has_special_chars': False,
            'has_suspicious_tld': False, 'has_suspicious_keyword': False,
            'has_suspicious_pattern': False, 'has_brand_name': False, 'brand_impersonation': False,
            'has_redirection': False, 'has_encoded_chars': False
        }
