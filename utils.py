import re
import tldextract
from urllib.parse import urlparse
import whois
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import socket
import dns.resolver
import hashlib
import json
import time
from urllib.parse import urljoin
import validators

class FeatureExtractor:
    """Advanced feature extractor for phishing detection"""
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', 
                       '.online', '.site', '.website', '.space', '.tech', '.review', 
                       '.bid', '.loan', '.date', '.download', '.country'}
    
    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = {
        'login', 'verify', 'account', 'update', 'secure', 'banking', 'paypal', 
        'amazon', 'apple', 'microsoft', 'confirm', 'validate', 'signin', 
        'authenticate', 'security', 'alert', 'warning', 'notice', 'restore',
        'unlock', 'suspended', 'verify-account', 'secure-login', 'webscr',
        'signin', 'ebayisapi', 'signin', 'paypal', 'cgi-bin', 'user', 'auth'
    }
    
    # URL shorteners
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 
        'adf.ly', 'short.link', 'tiny.cc', 'tr.im', 'v.gd', 'cli.gs',
        'shorturl.at', 'rb.gy', 'cutt.ly', 'tiny.one', 'shorte.st'
    }
    
    # Common legitimate domains (for typosquatting detection)
    LEGITIMATE_DOMAINS = {
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'paypal.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'yahoo.com', 'bing.com', 'duckduckgo.com', 'wikipedia.org', 'github.com',
        'stackoverflow.com', 'reddit.com', 'youtube.com', 'whatsapp.com', 'telegram.org'
    }
    
    @classmethod
    def extract_all_features(cls, url):
        """Extract all features from a URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        features = {}
        
        # URL-based features
        features.update(cls._extract_url_features(url))
        
        # Domain-based features
        features.update(cls._extract_domain_features(url))
        
        # Security features
        features.update(cls._extract_security_features(url))
        
        # Content-based features (optional, may increase response time)
        # features.update(cls._extract_content_features(url))
        
        return features
    
    @classmethod
    def _extract_url_features(cls, url):
        """Extract URL structure features"""
        features = {}
        
        # Basic length features
        features['url_length'] = min(len(url), 1000)
        parsed = urlparse(url)
        features['hostname_length'] = len(parsed.hostname or '')
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        
        # Special character counts
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersands'] = url.count('&')
        features['num_at_symbols'] = url.count('@')
        features['num_percent'] = url.count('%')
        features['num_colons'] = url.count(':')
        features['num_semicolons'] = url.count(';')
        
        # Character composition
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        features['digit_letter_ratio'] = features['num_digits'] / (features['num_letters'] + 1)
        
        # Entropy (measure of randomness)
        features['entropy'] = cls._calculate_entropy(url)
        
        # Suspicious patterns
        features['has_ip_address'] = 1 if cls._is_ip_address(parsed.hostname or '') else 0
        features['has_hex_chars'] = 1 if any(c in url.lower() for c in ['%2', '%3', '%4', '0x']) else 0
        
        # Double slash detection (excluding protocol)
        features['has_double_slash'] = 1 if '//' in url[8:] else 0
        
        return features
    
    @classmethod
    def _extract_domain_features(cls, url):
        """Extract domain-related features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ''
            extracted = tldextract.extract(url)
            
            # Domain characteristics
            features['domain_length'] = len(extracted.domain)
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['subdomain_length'] = len(extracted.subdomain)
            features['tld'] = extracted.suffix
            features['tld_length'] = len(extracted.suffix)
            
            # Suspicious TLD check
            features['is_suspicious_tld'] = 1 if f".{extracted.suffix}" in cls.SUSPICIOUS_TLDS else 0
            
            # Number of subdomains (suspicious if > 3)
            features['has_many_subdomains'] = 1 if features['subdomain_count'] > 3 else 0
            
            # Check for typosquatting
            features['has_typosquatting'] = cls._detect_typosquatting(extracted.domain, extracted.suffix)
            
            # Domain age (whois lookup)
            domain_age_features = cls._get_domain_age(domain)
            features.update(domain_age_features)
            
            # Brand name in subdomain (suspicious)
            features['has_brand_in_subdomain'] = cls._check_brand_in_subdomain(extracted.subdomain.lower())
            
        except Exception as e:
            # Default values if extraction fails
            features['domain_length'] = 0
            features['subdomain_count'] = 0
            features['subdomain_length'] = 0
            features['tld'] = ''
            features['tld_length'] = 0
            features['is_suspicious_tld'] = 0
            features['has_many_subdomains'] = 0
            features['has_typosquatting'] = 0
            features['domain_age_days'] = 0
            features['is_young_domain'] = 1
            features['days_since_registration'] = 0
            features['has_brand_in_subdomain'] = 0
        
        return features
    
    @classmethod
    def _extract_security_features(cls, url):
        """Extract security-related features"""
        features = {}
        
        # HTTPS check
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # Suspicious keywords in URL
        url_lower = url.lower()
        suspicious_count = sum(1 for keyword in cls.SUSPICIOUS_KEYWORDS if keyword in url_lower)
        features['suspicious_keyword_count'] = min(suspicious_count, 10)
        features['has_suspicious_keywords'] = 1 if suspicious_count > 0 else 0
        
        # URL shortener detection
        parsed = urlparse(url)
        domain = parsed.hostname or ''
        features['is_shortened'] = 1 if any(shortener in domain for shortener in cls.URL_SHORTENERS) else 0
        
        # Check for redirect patterns
        features['has_redirect'] = 1 if 'redirect' in url_lower or 'redir' in url_lower or 'return' in url_lower else 0
        
        # Check for fake login pages
        features['has_login_keyword'] = 1 if any(k in url_lower for k in ['login', 'signin', 'log-in', 'sign-in']) else 0
        
        # Check for multiple slashes (obfuscation)
        features['multiple_slashes'] = 1 if url.count('/') > 5 else 0
        
        return features
    
    @classmethod
    def _extract_content_features(cls, url):
        """Extract features from webpage content (optional, may be slow)"""
        features = {
            'has_forms': 0,
            'has_password_field': 0,
            'has_submit_button': 0,
            'num_external_links': 0,
            'num_internal_links': 0,
            'has_favicon': 0,
            'has_title': 0,
            'title_length': 0,
            'has_footer': 0,
            'has_copyright': 0,
            'num_scripts': 0,
            'num_iframes': 0
        }
        
        try:
            response = requests.get(url, timeout=5, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Form analysis
                forms = soup.find_all('form')
                features['has_forms'] = len(forms)
                
                # Check for password fields
                password_inputs = soup.find_all('input', {'type': 'password'})
                features['has_password_field'] = len(password_inputs)
                
                # Check for submit buttons
                submit_buttons = soup.find_all(['input', 'button'], {'type': 'submit'})
                features['has_submit_button'] = len(submit_buttons)
                
                # Link analysis
                all_links = soup.find_all('a', href=True)
                base_domain = urlparse(url).hostname
                for link in all_links:
                    href = link.get('href', '')
                    if href.startswith('http'):
                        if base_domain not in href:
                            features['num_external_links'] += 1
                        else:
                            features['num_internal_links'] += 1
                
                features['num_external_links'] = min(features['num_external_links'], 100)
                features['num_internal_links'] = min(features['num_internal_links'], 100)
                
                # Favicon
                features['has_favicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0
                
                # Title
                title_tag = soup.find('title')
                if title_tag and title_tag.string:
                    features['has_title'] = 1
                    features['title_length'] = len(title_tag.string.strip())
                
                # Footer and copyright
                features['has_footer'] = 1 if soup.find('footer') else 0
                features['has_copyright'] = 1 if 'copyright' in response.text.lower() or '©' in response.text else 0
                
                # Scripts and iframes
                features['num_scripts'] = len(soup.find_all('script'))
                features['num_iframes'] = len(soup.find_all('iframe'))
                
        except Exception:
            pass
        
        return features
    
    @staticmethod
    def _calculate_entropy(text):
        """Calculate Shannon entropy of a string"""
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * (p and __import__('math').log2(p)) for p in prob)
        return round(entropy, 2)
    
    @staticmethod
    def _is_ip_address(hostname):
        """Check if hostname is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, hostname))
    
    @classmethod
    def _detect_typosquatting(cls, domain, tld):
        """Detect typosquatting attempts"""
        domain_lower = domain.lower()
        for legitimate in cls.LEGITIMATE_DOMAINS:
            legit_domain = legitimate.split('.')[0]
            if legit_domain in domain_lower and legit_domain != domain_lower:
                # Check for common typosquatting patterns
                if (domain_lower.startswith(legit_domain) or 
                    domain_lower.endswith(legit_domain) or
                    legit_domain in domain_lower.replace(legit_domain, '', 1)):
                    return 1
        return 0
    
    @classmethod
    def _get_domain_age(cls, domain):
        """Get domain age using WHOIS lookup"""
        features = {
            'domain_age_days': 0,
            'is_young_domain': 1,
            'days_since_registration': 0
        }
        
        try:
            # Cache whois results to avoid rate limiting
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if creation_date:
                    age = (datetime.now() - creation_date).days
                    features['domain_age_days'] = min(age, 3650)  # Cap at 10 years
                    features['is_young_domain'] = 1 if age < 30 else 0
                    features['days_since_registration'] = age
        except:
            pass
        
        return features
    
    @classmethod
    def _check_brand_in_subdomain(cls, subdomain):
        """Check if brand names appear in subdomain (suspicious for phishing)"""
        brands = {'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'twitter'}
        return 1 if any(brand in subdomain for brand in brands) else 0


class MalwareScanner:
    """Advanced malware and threat detection scanner"""
    
    # Malware signature patterns
    MALWARE_PATTERNS = [
        (r'\.exe\b', 'Executable file download', 'HIGH', 'suspicious_file'),
        (r'\.bat\b', 'Batch script file', 'HIGH', 'suspicious_file'),
        (r'\.cmd\b', 'Command script', 'HIGH', 'suspicious_file'),
        (r'\.vbs\b', 'VBScript file', 'HIGH', 'suspicious_file'),
        (r'\.ps1\b', 'PowerShell script', 'HIGH', 'suspicious_file'),
        (r'\.scr\b', 'Screen saver executable', 'HIGH', 'suspicious_file'),
        (r'javascript:', 'JavaScript URI scheme', 'HIGH', 'dangerous_protocol'),
        (r'data:text/html', 'Data URI HTML content', 'HIGH', 'dangerous_protocol'),
        (r'vbscript:', 'VBScript URI scheme', 'HIGH', 'dangerous_protocol'),
        (r'eval\(', 'JavaScript eval() function', 'MEDIUM', 'obfuscation'),
        (r'document\.write\(', 'Dynamic content injection', 'MEDIUM', 'obfuscation'),
        (r'fromCharCode', 'Character code obfuscation', 'HIGH', 'obfuscation'),
        (r'unescape\(', 'Unescape function', 'MEDIUM', 'obfuscation'),
        (r'<script', 'Inline script injection', 'MEDIUM', 'code_injection'),
        (r'onload=', 'Event handler injection', 'LOW', 'code_injection'),
        (r'onclick=', 'Event handler injection', 'LOW', 'code_injection'),
        (r'onerror=', 'Event handler injection', 'LOW', 'code_injection'),
        (r'base64,', 'Base64 encoded content', 'MEDIUM', 'encoding'),
        (r'%3Cscript%3E', 'Encoded script tag', 'HIGH', 'encoded_attack'),
        (r'%3Ciframe%3E', 'Encoded iframe tag', 'HIGH', 'encoded_attack'),
    ]
    
    # Known malicious domain patterns
    MALICIOUS_PATTERNS = [
        'secure-verify', 'account-update', 'login-verify', 'confirm-identity',
        'verify-paypal', 'amazon-verify', 'apple-id-verify', 'microsoft-account',
        'bank-secure', 'payment-verify', 'security-check', 'validate-account'
    ]
    
    @classmethod
    def scan(cls, url):
        """Comprehensive malware scan"""
        results = {
            'has_malware': False,
            'detected_items': [],
            'threat_score': 0,
            'risk_factors': [],
            'scan_id': hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:8]
        }
        
        url_lower = url.lower()
        
        # Check malware patterns
        for pattern, name, severity, category in cls.MALWARE_PATTERNS:
            if re.search(pattern, url_lower):
                results['detected_items'].append({
                    'name': name,
                    'severity': severity,
                    'category': category,
                    'pattern': pattern
                })
                results['has_malware'] = True
        
        # Check for malicious patterns in URL
        for malicious_pattern in cls.MALICIOUS_PATTERNS:
            if malicious_pattern in url_lower:
                results['detected_items'].append({
                    'name': f'Suspicious pattern: {malicious_pattern}',
                    'severity': 'HIGH',
                    'category': 'url_pattern',
                    'pattern': malicious_pattern
                })
                results['has_malware'] = True
        
        # Check for IP-based URLs (common in phishing)
        parsed = urlparse(url)
        if FeatureExtractor._is_ip_address(parsed.hostname or ''):
            results['detected_items'].append({
                'name': 'IP address used as domain',
                'severity': 'HIGH',
                'category': 'suspicious_url',
                'pattern': 'ip_address'
            })
            results['has_malware'] = True
        
        # Calculate threat score
        if results['has_malware']:
            severity_scores = {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 15, 'LOW': 5}
            results['threat_score'] = min(sum(
                severity_scores.get(item['severity'], 10) for item in results['detected_items']
            ), 100)
        
        # Add risk factors
        if results['threat_score'] > 70:
            results['risk_factors'].append('Critical threat detected - Do not proceed')
        elif results['threat_score'] > 40:
            results['risk_factors'].append('High risk website detected')
        
        return results


class SecurityUtils:
    """Security utilities for request validation and sanitization"""
    
    @staticmethod
    def sanitize_url(url):
        """Sanitize and validate URL"""
        if not url:
            return None
        
        # Remove whitespace
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL
        if not validators.url(url):
            return None
        
        # Block local/private IPs
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        
        # Check for localhost
        if hostname in ('localhost', '127.0.0.1', '::1'):
            return None
        
        # Check for private IP ranges
        private_ip_patterns = [
            r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', r'^192\.168\.',
            r'^169\.254\.', r'^127\.'
        ]
        
        for pattern in private_ip_patterns:
            if re.match(pattern, hostname):
                return None
        
        return url
    
    @staticmethod
    def validate_request(data):
        """Validate incoming request data"""
        if not data or 'url' not in data:
            return False, "URL is required"
        
        url = data.get('url', '').strip()
        if not url:
            return False, "URL cannot be empty"
        
        if len(url) > 2000:
            return False, "URL too long (max 2000 characters)"
        
        return True, None
    
    @staticmethod
    def rate_limit_key(request):
        """Generate rate limit key from request"""
        return f"rate_limit:{request.remote_addr}"