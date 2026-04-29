import re
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
from datetime import datetime

# Download required NLTK data (run once)
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')
    nltk.download('wordnet')

class TextAnalyzer:
    """Advanced text analysis for phishing detection"""
    
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        self.lemmatizer = WordNetLemmatizer()
        
        # Phishing-specific keywords and patterns
        self.phishing_keywords = {
            'urgent': 10,
            'immediately': 10,
            'verify': 15,
            'confirm': 12,
            'account': 8,
            'suspended': 15,
            'security': 10,
            'alert': 10,
            'warning': 10,
            'update': 8,
            'information': 5,
            'click': 12,
            'link': 8,
            'login': 12,
            'password': 15,
            'credit card': 20,
            'ssn': 25,
            'bank account': 20,
            'limited time': 10,
            'expires': 8
        }
        
        self.suspicious_patterns = [
            (r'\b\d{16}\b', 'Credit card number'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN format'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
            (r'\b\d{10}\b', 'Phone number'),
            (r'bit\.ly|tinyurl|goo\.gl', 'URL shortener')
        ]
        
        self.sentiment_keywords = {
            'fear': ['scam', 'fraud', 'stolen', 'hacked', 'unauthorized'],
            'urgency': ['now', 'today', 'immediately', 'asap', 'fast'],
            'authority': ['official', 'legal', 'required', 'must', 'mandatory']
        }
    
    def analyze(self, text):
        """Analyze text for phishing indicators"""
        try:
            # Preprocess text
            cleaned_text = self.preprocess_text(text)
            tokens = self.tokenize(cleaned_text)
            
            # Extract features
            features = self.extract_features(text, cleaned_text, tokens)
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(features)
            
            # Identify threats
            threats = self.identify_threats(text, features)
            
            # Determine status
            if risk_score >= 70:
                status = 'danger'
                message = '⚠️ CRITICAL: Text contains multiple phishing indicators'
            elif risk_score >= 40:
                status = 'warning'
                message = '⚠️ WARNING: Text shows suspicious patterns'
            else:
                status = 'safe'
                message = '✅ SAFE: Text appears legitimate'
            
            return {
                'risk_score': risk_score,
                'status': status,
                'message': message,
                'threats': threats,
                'features': features,
                'word_count': len(tokens),
                'sentence_count': len(sent_tokenize(text)),
                'recommendation': self.get_recommendation(status),
                'timestamp': datetime.now().isoformat(),
                'analysis_type': 'text'
            }
            
        except Exception as e:
            print(f"Error analyzing text: {e}")
            return self.get_error_result()
    
    def preprocess_text(self, text):
        """Preprocess text for analysis"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep important ones
        text = re.sub(r'[^a-zA-Z0-9\s@\.\-]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def tokenize(self, text):
        """Tokenize text into words"""
        tokens = word_tokenize(text)
        
        # Remove stop words and lemmatize
        tokens = [self.lemmatizer.lemmatize(token) for token in tokens 
                  if token not in self.stop_words and token.isalpha()]
        
        return tokens
    
    def extract_features(self, original_text, cleaned_text, tokens):
        """Extract comprehensive text features"""
        features = {}
        
        # Basic statistics
        features['word_count'] = len(tokens)
        features['char_count'] = len(original_text)
        features['sentence_count'] = len(sent_tokenize(original_text))
        
        # Keyword presence
        features['phishing_keywords'] = []
        features['phishing_keyword_score'] = 0
        
        for keyword, score in self.phishing_keywords.items():
            if keyword in cleaned_text:
                features['phishing_keywords'].append(keyword)
                features['phishing_keyword_score'] += score
        
        # Check for suspicious patterns
        features['suspicious_patterns'] = []
        for pattern, description in self.suspicious_patterns:
            if re.search(pattern, original_text):
                features['suspicious_patterns'].append(description)
        
        # Sentiment analysis
        features['sentiment'] = self.analyze_sentiment(cleaned_text)
        
        # Language complexity
        if features['sentence_count'] > 0:
            avg_word_length = sum(len(word) for word in tokens) / len(tokens) if tokens else 0
            features['avg_word_length'] = avg_word_length
            features['avg_sentence_length'] = len(tokens) / features['sentence_count']
        
        # Check for all caps words (shouting)
        all_caps_words = re.findall(r'\b[A-Z]{3,}\b', original_text)
        features['all_caps_count'] = len(all_caps_words)
        
        # Check for exclamation marks (urgency)
        features['exclamation_count'] = original_text.count('!')
        
        # Check for URLs
        urls = re.findall(r'https?://[^\s]+', original_text)
        features['url_count'] = len(urls)
        
        # Check for HTML tags
        html_tags = re.findall(r'<[^>]+>', original_text)
        features['html_tag_count'] = len(html_tags)
        
        return features
    
    def analyze_sentiment(self, text):
        """Simple sentiment analysis for phishing detection"""
        sentiment = {
            'fear_score': 0,
            'urgency_score': 0,
            'authority_score': 0
        }
        
        text_lower = text.lower()
        
        for category, keywords in self.sentiment_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    if category == 'fear':
                        sentiment['fear_score'] += 10
                    elif category == 'urgency':
                        sentiment['urgency_score'] += 8
                    elif category == 'authority':
                        sentiment['authority_score'] += 7
        
        # Cap scores
        for key in sentiment:
            sentiment[key] = min(sentiment[key], 50)
        
        return sentiment
    
    def calculate_risk_score(self, features):
        """Calculate overall risk score"""
        risk_score = 0
        
        # Keyword risk
        risk_score += min(features['phishing_keyword_score'], 40)
        
        # Suspicious patterns risk
        risk_score += len(features['suspicious_patterns']) * 15
        
        # Sentiment risk
        risk_score += features['sentiment']['fear_score'] * 0.3
        risk_score += features['sentiment']['urgency_score'] * 0.4
        risk_score += features['sentiment']['authority_score'] * 0.3
        
        # All caps risk
        risk_score += min(features['all_caps_count'] * 5, 15)
        
        # Exclamation marks risk
        risk_score += min(features['exclamation_count'] * 3, 10)
        
        # URL risk
        if features['url_count'] > 0:
            risk_score += min(features['url_count'] * 10, 20)
        
        # HTML tags risk (could be hidden content)
        if features['html_tag_count'] > 0:
            risk_score += 15
        
        # Cap at 100
        return min(risk_score, 100)
    
    def identify_threats(self, text, features):
        """Identify specific threats in text"""
        threats = []
        
        # Check for phishing keywords
        if features['phishing_keywords']:
            keywords = ', '.join(features['phishing_keywords'][:5])
            threats.append(f'Suspicious keywords detected: {keywords}')
        
        # Check for suspicious patterns
        for pattern in features['suspicious_patterns']:
            threats.append(f'Sensitive information pattern: {pattern}')
        
        # Check sentiment
        if features['sentiment']['fear_score'] > 30:
            threats.append('High fear-inducing language detected')
        if features['sentiment']['urgency_score'] > 30:
            threats.append('High urgency language detected - pressure tactic')
        if features['sentiment']['authority_score'] > 30:
            threats.append('Authority language detected - potential impersonation')
        
        # Check for excessive caps
        if features['all_caps_count'] > 3:
            threats.append('Excessive use of capital letters - aggressive tone')
        
        # Check for excessive exclamation
        if features['exclamation_count'] > 5:
            threats.append('Excessive exclamation marks - emotional manipulation')
        
        # Check for URLs
        if features['url_count'] > 0:
            threats.append(f'Contains {features["url_count"]} URL(s) - potential redirection')
        
        return threats
    
    def get_recommendation(self, status):
        """Get recommendation based on status"""
        if status == 'danger':
            return '🚫 Do not trust this content. It contains multiple phishing indicators.'
        elif status == 'warning':
            return '⚠️ Be cautious. Verify the source and do not take immediate action.'
        else:
            return '✓ Text appears safe, but always verify unexpected requests.'
    
    def get_error_result(self):
        """Return error result"""
        return {
            'risk_score': 100,
            'status': 'danger',
            'message': '⚠️ ERROR: Unable to analyze text',
            'threats': ['Text analysis failed'],
            'features': {},
            'word_count': 0,
            'sentence_count': 0,
            'recommendation': 'Unable to analyze this text. Exercise caution.',
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'text_error'
        }
