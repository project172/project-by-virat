from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sys
import logging
from datetime import datetime
import json
import hashlib
import secrets

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import custom modules
from backend.features.url_features import URLAnalyzer
from backend.features.email_features import EmailAnalyzer
from backend.features.image_features import ImageAnalyzer
from backend.nlp.text_analyzer import TextAnalyzer
from backend.image_analysis.logo_detector import LogoDetector
from backend.utils.helpers import SecurityUtils, Logger

# Initialize Flask app
app = Flask(__name__, 
            static_folder='../frontend/static',
            template_folder='../frontend/templates')

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['RATELIMIT_ENABLED'] = True

# Create upload directory if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Enable CORS
CORS(app)

# Initialize analyzers
url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()
image_analyzer = ImageAnalyzer()
text_analyzer = TextAnalyzer()
logo_detector = LogoDetector()
security_utils = SecurityUtils()
logger = Logger()

# In-memory cache for results (in production, use Redis)
analysis_cache = {}
CACHE_SIZE = 100

@app.route('/')
@limiter.limit("100 per minute")
def index():
    """Serve main page"""
    try:
        return render_template('index.html')
    except Exception as e:
        logger.log_error(f"Error serving index: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory(app.static_folder, filename)

@app.route('/analyze/url', methods=['POST'])
@limiter.limit("30 per minute")
def analyze_url():
    """Analyze URL for phishing indicators"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Validate URL
        if not security_utils.validate_url(url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Check cache
        cache_key = hashlib.md5(f"url_{url}".encode()).hexdigest()
        if cache_key in analysis_cache:
            logger.log_info(f"Cache hit for URL: {url}")
            return jsonify(analysis_cache[cache_key])
        
        # Analyze URL
        result = url_analyzer.analyze(url)
        
        # Store in cache
        if len(analysis_cache) >= CACHE_SIZE:
            # Remove oldest entry
            oldest_key = next(iter(analysis_cache))
            del analysis_cache[oldest_key]
        analysis_cache[cache_key] = result
        
        logger.log_info(f"URL analysis completed: {url} - Risk Score: {result['risk_score']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.log_error(f"Error analyzing URL: {str(e)}")
        return jsonify({'error': 'Analysis failed. Please try again.'}), 500

@app.route('/analyze/email', methods=['POST'])
@limiter.limit("20 per minute")
def analyze_email():
    """Analyze email content for phishing"""
    try:
        data = request.get_json()
        email_content = data.get('content', '').strip()
        email_subject = data.get('subject', '').strip()
        
        if not email_content:
            return jsonify({'error': 'No email content provided'}), 400
        
        # Analyze email
        result = email_analyzer.analyze(email_content, email_subject)
        
        logger.log_info(f"Email analysis completed - Risk Score: {result['risk_score']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.log_error(f"Error analyzing email: {str(e)}")
        return jsonify({'error': 'Email analysis failed'}), 500

@app.route('/analyze/image', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_image():
    """Analyze image for phishing indicators"""
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not security_utils.validate_file_type(file.filename):
            return jsonify({'error': 'Invalid file type. Only images allowed.'}), 400
        
        # Save file temporarily
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                                 f"{datetime.now().timestamp()}_{file.filename}")
        file.save(file_path)
        
        try:
            # Analyze image
            result = image_analyzer.analyze(file_path)
            
            # Also perform logo detection
            logo_result = logo_detector.detect(file_path)
            result['logo_analysis'] = logo_result
            
            logger.log_info(f"Image analysis completed - Suspicious: {result['is_suspicious']}")
            
            return jsonify(result)
            
        finally:
            # Clean up file
            if os.path.exists(file_path):
                os.remove(file_path)
        
    except Exception as e:
        logger.log_error(f"Error analyzing image: {str(e)}")
        return jsonify({'error': 'Image analysis failed'}), 500

@app.route('/analyze/text', methods=['POST'])
@limiter.limit("30 per minute")
def analyze_text():
    """Analyze text content for phishing patterns"""
    try:
        data = request.get_json()
        text = data.get('text', '').strip()
        
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Analyze text
        result = text_analyzer.analyze(text)
        
        logger.log_info(f"Text analysis completed - Risk Score: {result['risk_score']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.log_error(f"Error analyzing text: {str(e)}")
        return jsonify({'error': 'Text analysis failed'}), 500

@app.route('/analyze/comprehensive', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_comprehensive():
    """Perform comprehensive analysis combining multiple checks"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        email_content = data.get('email', '').strip()
        text_content = data.get('text', '').strip()
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'url_analysis': None,
            'email_analysis': None,
            'text_analysis': None,
            'overall_risk_score': 0,
            'overall_status': 'safe',
            'total_threats': []
        }
        
        # Analyze URL if provided
        if url and security_utils.validate_url(url):
            results['url_analysis'] = url_analyzer.analyze(url)
            results['overall_risk_score'] += results['url_analysis']['risk_score'] * 0.4
            results['total_threats'].extend(results['url_analysis']['threats'])
        
        # Analyze email if provided
        if email_content:
            results['email_analysis'] = email_analyzer.analyze(email_content, '')
            results['overall_risk_score'] += results['email_analysis']['risk_score'] * 0.3
            results['total_threats'].extend(results['email_analysis']['threats'])
        
        # Analyze text if provided
        if text_content:
            results['text_analysis'] = text_analyzer.analyze(text_content)
            results['overall_risk_score'] += results['text_analysis']['risk_score'] * 0.3
            results['total_threats'].extend(results['text_analysis']['threats'])
        
        # Calculate overall risk score
        if any([url, email_content, text_content]):
            results['overall_risk_score'] = min(100, results['overall_risk_score'])
            
            # Determine overall status
            if results['overall_risk_score'] >= 70:
                results['overall_status'] = 'danger'
            elif results['overall_risk_score'] >= 40:
                results['overall_status'] = 'warning'
            else:
                results['overall_status'] = 'safe'
        
        # Remove duplicates from threats
        results['total_threats'] = list(set(results['total_threats']))
        
        logger.log_info(f"Comprehensive analysis completed - Overall Risk: {results['overall_risk_score']}")
        
        return jsonify(results)
        
    except Exception as e:
        logger.log_error(f"Error in comprehensive analysis: {str(e)}")
        return jsonify({'error': 'Comprehensive analysis failed'}), 500

@app.route('/api/stats', methods=['GET'])
@limiter.limit("10 per minute")
def get_stats():
    """Get system statistics"""
    try:
        stats = {
            'total_analyses': logger.get_analysis_count(),
            'cache_size': len(analysis_cache),
            'system_status': 'operational',
            'timestamp': datetime.now().isoformat(),
            'version': '2.0.0'
        }
        return jsonify(stats)
    except Exception as e:
        logger.log_error(f"Error getting stats: {str(e)}")
        return jsonify({'error': 'Unable to fetch stats'}), 500

@app.route('/api/clear_cache', methods=['POST'])
@limiter.limit("5 per hour")
def clear_cache():
    """Clear analysis cache (admin only)"""
    try:
        # In production, add authentication here
        analysis_cache.clear()
        logger.log_info("Cache cleared")
        return jsonify({'message': 'Cache cleared successfully'})
    except Exception as e:
        logger.log_error(f"Error clearing cache: {str(e)}")
        return jsonify({'error': 'Unable to clear cache'}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(429)
def ratelimit_error(error):
    """Handle rate limit errors"""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(500)
def internal_error(error):
    """Handle internal errors"""
    logger.log_error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Run the app
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
