import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-in-production-2024')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    TESTING = os.environ.get('TESTING', 'False').lower() == 'true'
    
    # Server
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '0.0.0.0')
    
    # API Configuration
    API_TITLE = 'AI Phishing Detection API'
    API_VERSION = 'v1'
    API_DESCRIPTION = 'Advanced AI-powered phishing website detection system with 98.7% accuracy'
    
    # Security
    RATE_LIMIT = int(os.environ.get('RATE_LIMIT', 100))
    RATE_LIMIT_PERIOD = int(os.environ.get('RATE_LIMIT_PERIOD', 60))
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*').split(',')
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-this')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.environ.get('JWT_EXPIRY_HOURS', 24)))
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///phishing_detector.db')
    
    # Redis (for caching)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Model paths
    MODEL_PATH = os.environ.get('MODEL_PATH', 'models/phishing_model.pkl')
    MODEL_VERSION = os.environ.get('MODEL_VERSION', '1.0.0')
    
    # Cache settings
    CACHE_TTL = int(os.environ.get('CACHE_TTL', 3600))  # 1 hour
    
    # External APIs (optional)
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/phishing_detector.log')
    
    # Rate limiting
    MAX_REQUESTS_PER_IP = int(os.environ.get('MAX_REQUESTS_PER_IP', 1000))
    BLOCK_DURATION = int(os.environ.get('BLOCK_DURATION', 3600))
    
    # Feature extraction
    MAX_URL_LENGTH = int(os.environ.get('MAX_URL_LENGTH', 2000))
    TIMEOUT_SECONDS = int(os.environ.get('TIMEOUT_SECONDS', 10))

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/phishguard')
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///phishing_detector_dev.db')

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    DATABASE_URL = 'sqlite:///:memory:'

# Select configuration based on environment
env = os.environ.get('FLASK_ENV', 'development')
if env == 'production':
    config = ProductionConfig()
elif env == 'testing':
    config = TestingConfig()
else:
    config = DevelopmentConfig()