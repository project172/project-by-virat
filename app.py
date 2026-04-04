from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_restx import Api, Resource, fields
from datetime import datetime
import time
import json
import logging
from logging.handlers import RotatingFileHandler
import os

from config import config
from utils import FeatureExtractor, MalwareScanner, SecurityUtils
from ml_model import detector
from database import db_manager

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['JSON_SORT_KEYS'] = False

# Enable CORS
CORS(app, origins=config.ALLOWED_ORIGINS)

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler(config.LOG_FILE, maxBytes=10485760, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(getattr(logging, config.LOG_LEVEL))
app.logger.addHandler(file_handler)
app.logger.setLevel(getattr(logging, config.LOG_LEVEL))
app.logger.info('AI Phishing Detection Tool startup')

# Initialize API
api = Api(app, 
          title=config.API_TITLE,
          version=config.API_VERSION,
          description=config.API_DESCRIPTION,
          doc='/api/docs',
          authorizations={
              'apikey': {
                  'type': 'apiKey',
                  'in': 'header',
                  'name': 'X-API-Key'
              }
          })

# Define API models
analysis_model = api.model('AnalysisRequest', {
    'url': fields.String(required=True, description='URL to analyze', example='https://example.com')
})

analysis_response = api.model('AnalysisResponse', {
    'is_phishing': fields.Boolean(description='Whether the URL is phishing'),
    'confidence': fields.Float(description='Confidence score (0-100)'),
    'risk_score': fields.Float(description='Risk score (0-100)'),
    'risk_level': fields.String(description='Risk level (Low/Medium/High/Critical)'),
    'malware_detected': fields.Boolean(description='Whether malware was detected'),
    'malware_details': fields.List(fields.String, description='Detected malware details'),
    'threat_score': fields.Float(description='Threat score (0-100)'),
    'ssl_valid': fields.Boolean(description='Whether SSL certificate is valid'),
    'features': fields.Raw(description='Extracted features'),
    'analysis_timestamp': fields.String(description='Analysis timestamp'),
    'scan_id': fields.String(description='Unique scan identifier')
})

# Middleware for request logging and rate limiting
@app.before_request
def before_request():
    """Pre-processing before each request"""
    request.start_time = time.time()
    
    # Rate limiting
    if request.endpoint and not request.endpoint.startswith('static'):
        ip = request.remote_addr
        allowed, blocked_until = db_manager.check_rate_limit(ip, config.RATE_LIMIT, config.RATE_LIMIT_PERIOD)
        
        if not allowed:
            return jsonify({
                'error': 'Rate limit exceeded',
                'message': f'Too many requests. Try again after {blocked_until}',
                'retry_after': blocked_until.isoformat() if blocked_until else None
            }), 429

@app.after_request
def after_request(response):
    """Post-processing after each request"""
    if hasattr(request, 'start_time'):
        response_time = (time.time() - request.start_time) * 1000
        
        # Log API request
        if request.endpoint and not request.endpoint.startswith('static'):
            db_manager.log_api_request(
                endpoint=request.endpoint,
                method=request.method,
                ip_address=request.remote_addr,
                status_code=response.status_code,
                response_time=response_time,
                request_data=request.get_json() if request.is_json else None
            )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Routes
@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': config.API_VERSION,
        'model_loaded': detector.is_trained,
        'model_version': detector.model_version
    })

@api.route('/api/analyze')
class AnalyzeURL(Resource):
    @api.expect(analysis_model)
    @api.response(200, 'Success', analysis_response)
    @api.response(400, 'Invalid URL')
    @api.response(429, 'Rate limit exceeded')
    def post(self):
        """Analyze a URL for phishing and malware detection"""
        start_time = time.time()
        
        # Validate request
        data = request.get_json()
        is_valid, error_message = SecurityUtils.validate_request(data)
        
        if not is_valid:
            return {'error': error_message}, 400
        
        url = data.get('url', '').strip()
        
        # Sanitize URL
        url = SecurityUtils.sanitize_url(url)
        if not url:
            return {'error': 'Invalid or blocked URL'}, 400
        
        app.logger.info(f"Analyzing URL: {url} from IP: {request.remote_addr}")
        
        try:
            # Extract features
            features = FeatureExtractor.extract_all_features(url)
            
            # Scan for malware
            malware_scan = MalwareScanner.scan(url)
            
            # AI Prediction
            is_phishing, confidence = detector.predict(features)
            
            # Calculate risk score
            risk_score = 0
            
            # Weighted risk factors
            if not features.get('has_https', 0):
                risk_score += 25
            if features.get('has_suspicious_keywords', 0):
                risk_score += 20
            if features.get('has_ip_address', 0):
                risk_score += 30
            if features.get('is_shortened', 0):
                risk_score += 15
            if features.get('has_typosquatting', 0):
                risk_score += 25
            if features.get('has_many_subdomains', 0):
                risk_score += 10
            if features.get('is_young_domain', 0):
                risk_score += 20
            if features.get('suspicious_keyword_count', 0) > 2:
                risk_score += 15
            
            # Add malware contribution
            if malware_scan['has_malware']:
                risk_score += malware_scan['threat_score'] * 0.5
            
            # Adjust based on AI confidence
            if is_phishing:
                risk_score = max(risk_score, 50)
            
            risk_score = min(risk_score, 100)
            
            # Determine risk level
            if risk_score > 75:
                risk_level = 'CRITICAL'
            elif risk_score > 50:
                risk_level = 'HIGH'
            elif risk_score > 30:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Override if malware detected
            if malware_scan['has_malware']:
                is_phishing = True
                if malware_scan['threat_score'] > 70:
                    risk_level = 'CRITICAL'
                else:
                    risk_level = 'HIGH'
            
            # Check threat intelligence database
            from urllib.parse import urlparse
            domain = urlparse(url).hostname or ''
            threat_intel = db_manager.check_threat_intelligence(domain)
            
            if threat_intel['is_threat']:
                is_phishing = True
                risk_level = threat_intel['severity']
                risk_score = max(risk_score, 70)
            
            response_time = (time.time() - start_time) * 1000
            
            # Prepare response
            response = {
                'is_phishing': is_phishing,
                'confidence': round(confidence * 100, 1),
                'risk_score': round(risk_score, 1),
                'risk_level': risk_level,
                'malware_detected': malware_scan['has_malware'],
                'malware_details': [m['name'] for m in malware_scan['detected_items']],
                'threat_score': malware_scan['threat_score'],
                'ssl_valid': features.get('has_https', 0) == 1,
                'features': {k: v for k, v in features.items() if not isinstance(v, (dict, list))},
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'scan_id': malware_scan['scan_id'],
                'response_time_ms': round(response_time, 2)
            }
            
            # Save to database
            db_manager.save_analysis({
                'url': url,
                'is_phishing': is_phishing,
                'confidence': confidence,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'malware_detected': malware_scan['has_malware'],
                'malware_details': json.dumps(malware_scan['detected_items']),
                'threat_score': malware_scan['threat_score'],
                'features_used': json.dumps(features),
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'response_time': response_time
            })
            
            # Add to threat intelligence if phishing detected
            if is_phishing and risk_level in ['HIGH', 'CRITICAL']:
                db_manager.add_threat_intelligence(domain, 'phishing', risk_level, 'ai_detection')
            
            app.logger.info(f"Analysis complete for {url}: {'Phishing' if is_phishing else 'Legitimate'} (Confidence: {confidence:.2%})")
            
            return response
            
        except Exception as e:
            app.logger.error(f"Analysis error for {url}: {str(e)}")
            return {
                'error': 'Analysis failed',
                'message': str(e),
                'is_phishing': False,
                'confidence': 50
            }, 500

@api.route('/api/stats')
class GetStats(Resource):
    def get(self):
        """Get overall statistics"""
        try:
            stats = db_manager.get_statistics()
            return {
                'success': True,
                'data': stats,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            app.logger.error(f"Stats error: {str(e)}")
            return {'success': False, 'error': str(e)}, 500

@api.route('/api/history')
class GetHistory(Resource):
    def get(self):
        """Get recent analysis history"""
        try:
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)
            
            limit = min(limit, 100)  # Cap at 100
            
            history = db_manager.get_recent_analyses(limit, offset)
            return {
                'success': True,
                'data': history,
                'count': len(history),
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            app.logger.error(f"History error: {str(e)}")
            return {'success': False, 'error': str(e)}, 500

@api.route('/api/model/info')
class ModelInfo(Resource):
    def get(self):
        """Get model information"""
        return {
            'model_loaded': detector.is_trained,
            'model_version': detector.model_version,
            'training_accuracy': detector.training_accuracy,
            'features_count': len(detector.feature_names),
            'feature_importance': detector.feature_importance,
            'top_features': list(detector.feature_importance.keys())[:10]
        }

@api.route('/api/batch-analyze')
class BatchAnalyze(Resource):
    @api.expect(api.model('BatchRequest', {
        'urls': fields.List(fields.String, required=True, description='List of URLs to analyze')
    }))
    def post(self):
        """Analyze multiple URLs in batch"""
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or len(urls) > 10:
            return {'error': 'Provide 1-10 URLs for batch analysis'}, 400
        
        results = []
        for url in urls[:10]:  # Limit to 10 URLs
            try:
                # Sanitize URL
                url = SecurityUtils.sanitize_url(url)
                if not url:
                    results.append({'url': url, 'error': 'Invalid URL', 'is_phishing': False})
                    continue
                
                # Extract features
                features = FeatureExtractor.extract_all_features(url)
                
                # AI Prediction
                is_phishing, confidence = detector.predict(features)
                
                results.append({
                    'url': url,
                    'is_phishing': is_phishing,
                    'confidence': round(confidence * 100, 1),
                    'risk_score': round((1 - confidence) * 100, 1) if is_phishing else round(confidence * 100, 1)
                })
            except Exception as e:
                results.append({'url': url, 'error': str(e), 'is_phishing': False})
        
        return {
            'success': True,
            'results': results,
            'total_analyzed': len(results),
            'timestamp': datetime.utcnow().isoformat()
        }

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        threaded=True
    )