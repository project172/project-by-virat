import re
from email.utils import parseaddr
import hashlib
from datetime import datetime

class EmailAnalyzer:
    """Email content analysis for phishing detection"""
    
    def __init__(self):
        self.suspicious_senders = ['support', 'security', 'verify', 'admin', 'service', 
                                    'noreply', 'notification', 'alert', 'update']
        
        self.urgency_keywords = ['urgent', 'immediately', 'asap', 'action required', 
                                   'account suspended', 'verify now', 'click here', 
                                   'limited time', 'expires', 'warning', 'security alert']
        
        self.suspicious_phrases = ['verify your account', 'confirm your identity', 
                                     'update your information', 'unusual activity', 
                                     'account will be closed', 'click to confirm']
        
        self.suspicious_attachments = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', 
                                         '.zip', '.rar', '.docm', '.xlsm']
    
    def analyze(self, email_content, subject=''):
        """Analyze email for phishing indicators"""
        risk_score = 0
        threats = []
        
        # Extract email components
        sender = self.extract_sender(email_content)
        links = self.extract_links(email_content)
        attachments = self.extract_attachments(email_content)
        
        # Check sender
        if self.is_suspicious_sender(sender):
            risk_score += 20
            threats.append(f'Suspicious sender address: {sender}')
        
        # Check subject for urgency
        if subject:
            urgency_score, urgency_threats = self.check_urgency(subject)
            risk_score += urgency_score
            threats.extend(urgency_threats)
        
        # Check content for suspicious phrases
        phrase_score, phrase_threats = self.check_suspicious_phrases(email_content)
        risk_score += phrase_score
        threats.extend(phrase_threats)
        
        # Check links
        for link in links:
            link_score, link_threat = self.analyze_link(link)
            risk_score += link_score
            if link_threat:
                threats.append(link_threat)
        
        # Check attachments
        for attachment in attachments:
            if self.is_suspicious_attachment(attachment):
                risk_score += 25
                threats.append(f'Suspicious attachment: {attachment}')
        
        # Check for spoofed display names
        if self.is_spoofed_display_name(email_content):
            risk_score += 15
            threats.append('Spoofed display name detected')
        
        # Check for mismatched URLs
        mismatched_urls = self.check_mismatched_urls(email_content)
        if mismatched_urls:
            risk_score += 20
            threats.append(f'Mismatched URLs detected: {mismatched_urls}')
        
        # Cap risk score
        risk_score = min(risk_score, 100)
        
        # Determine status
        if risk_score >= 70:
            status = 'danger'
            message = '⚠️ CRITICAL: This email appears to be a PHISHING attempt!'
        elif risk_score >= 40:
            status = 'warning'
            message = '⚠️ WARNING: This email shows suspicious characteristics'
        else:
            status = 'safe'
            message = '✅ SAFE: This email appears legitimate'
        
        return {
            'risk_score': risk_score,
            'status': status,
            'message': message,
            'threats': threats,
            'links_found': len(links),
            'attachments_found': len(attachments),
            'sender': sender,
            'recommendation': self.get_recommendation(status),
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'email'
        }
    
    def extract_sender(self, email_content):
        """Extract sender email address"""
        # Simple regex for email extraction
        match = re.search(r'From:.*?<(.+?)>', email_content, re.IGNORECASE)
        if match:
            return match.group(1)
        
        match = re.search(r'From:\s*(\S+@\S+)', email_content, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return 'unknown'
    
    def extract_links(self, email_content):
        """Extract all links from email"""
        # Simple regex for URL extraction
        urls = re.findall(r'https?://[^\s<>"]+', email_content)
        return list(set(urls))
    
    def extract_attachments(self, email_content):
        """Extract attachment names"""
        # Simple pattern for attachments
        attachments = re.findall(r'filename="([^"]+)"', email_content, re.IGNORECASE)
        attachments.extend(re.findall(r'filename=([^\s;]+)', email_content, re.IGNORECASE))
        return list(set(attachments))
    
    def is_suspicious_sender(self, sender):
        """Check if sender is suspicious"""
        sender_lower = sender.lower()
        for suspicious in self.suspicious_senders:
            if suspicious in sender_lower:
                return True
        return False
    
    def check_urgency(self, text):
        """Check for urgency indicators"""
        score = 0
        threats = []
        text_lower = text.lower()
        
        for keyword in self.urgency_keywords:
            if keyword in text_lower:
                score += 10
                threats.append(f'Urgency keyword detected: "{keyword}"')
        
        return min(score, 30), threats
    
    def check_suspicious_phrases(self, text):
        """Check for suspicious phrases"""
        score = 0
        threats = []
        text_lower = text.lower()
        
        for phrase in self.suspicious_phrases:
            if phrase in text_lower:
                score += 15
                threats.append(f'Suspicious phrase: "{phrase}"')
        
        return min(score, 40), threats
    
    def analyze_link(self, link):
        """Analyze a single link for suspicious patterns"""
        score = 0
        threat = None
        
        # Check for IP address
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', link):
            score += 20
            threat = f'IP address link detected: {link}'
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz']
        for tld in suspicious_tlds:
            if tld in link:
                score += 15
                threat = f'Suspicious TLD in link: {link}'
                break
        
        # Check for long URLs
        if len(link) > 100:
            score += 5
        
        return min(score, 25), threat
    
    def is_suspicious_attachment(self, filename):
        """Check if attachment is suspicious"""
        filename_lower = filename.lower()
        for ext in self.suspicious_attachments:
            if filename_lower.endswith(ext):
                return True
        return False
    
    def is_spoofed_display_name(self, email_content):
        """Check for spoofed display names"""
        # Look for patterns like "PayPal <scammer@fake.com>"
        spoofed_patterns = [
            r'[A-Za-z]+\s+<[^>]+@[^>]+>',  # Name <email>
            r'"([^"]+)"\s+<[^>]+@[^>]+>'    # "Name" <email>
        ]
        
        for pattern in spoofed_patterns:
            matches = re.findall(pattern, email_content)
            for match in matches:
                if isinstance(match, tuple):
                    name = match[0]
                else:
                    name = match.split('<')[0].strip().strip('"')
                
                # Check if name is a legitimate brand but email is suspicious
                brands = ['PayPal', 'Amazon', 'Google', 'Microsoft', 'Apple']
                if any(brand in name for brand in brands):
                    return True
        
        return False
    
    def check_mismatched_urls(self, email_content):
        """Check for mismatched URLs (display text vs actual link)"""
        mismatches = []
        
        # Find patterns like <a href="bad.com">good.com</a>
        pattern = r'<a\s+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(pattern, email_content, re.IGNORECASE)
        
        for actual, display in matches:
            # Extract domain from actual URL
            actual_domain = re.sub(r'https?://', '', actual).split('/')[0]
            display_domain = re.sub(r'https?://', '', display).split('/')[0]
            
            if actual_domain != display_domain:
                mismatches.append(f'"{display}" links to "{actual}"')
        
        return mismatches if mismatches else None
    
    def get_recommendation(self, status):
        """Get recommendation based on status"""
        if status == 'danger':
            return '🚫 DO NOT click any links, download attachments, or reply. Report this email as phishing.'
        elif status == 'warning':
            return '⚠️ Be cautious. Verify the sender through another channel before taking any action.'
        else:
            return '✓ Email appears safe, but always verify unexpected requests for sensitive information.'
