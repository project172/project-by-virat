import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import os
import json
import warnings
from datetime import datetime
warnings.filterwarnings('ignore')

class AdvancedPhishingDetector:
    """Advanced AI-based Phishing Detection Model with Ensemble Learning"""
    
    def __init__(self):
        self.model = None
        self.scaler = RobustScaler()
        self.feature_selector = None
        self.is_trained = False
        self.training_accuracy = 0
        self.feature_importance = {}
        self.model_version = "2.0.0"
        
        # Comprehensive feature list (42 features)
        self.feature_names = [
            # URL Structure Features (15)
            'url_length', 'hostname_length', 'path_length', 'query_length',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equals', 'num_ampersands', 'num_at_symbols',
            'num_percent', 'num_colons', 'num_semicolons',
            
            # Character Composition (4)
            'num_digits', 'num_letters', 'digit_letter_ratio', 'entropy',
            
            # Domain Features (11)
            'domain_length', 'subdomain_count', 'subdomain_length', 'tld_length',
            'is_suspicious_tld', 'has_many_subdomains', 'has_typosquatting',
            'domain_age_days', 'is_young_domain', 'days_since_registration',
            'has_brand_in_subdomain',
            
            # Security Features (9)
            'has_https', 'suspicious_keyword_count', 'has_suspicious_keywords',
            'is_shortened', 'has_redirect', 'has_login_keyword', 'multiple_slashes',
            'has_ip_address', 'has_hex_chars',
            
            # Content Features (3 - optional)
            'has_forms', 'has_password_field', 'has_submit_button'
        ]
        
        # Feature weights for importance scoring
        self.feature_weights = {
            'has_ip_address': 3.0,
            'has_typosquatting': 2.5,
            'is_young_domain': 2.0,
            'has_suspicious_keywords': 2.0,
            'is_shortened': 1.8,
            'has_redirect': 1.5,
            'is_suspicious_tld': 1.5,
            'has_many_subdomains': 1.3,
            'has_login_keyword': 1.2,
            'has_https': 1.2
        }
    
    def train(self, X_train, y_train, use_grid_search=False):
        """Train the ensemble model"""
        print("Starting model training...")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Feature selection (keep top 90% features)
        self.feature_selector = SelectKBest(f_classif, k=min(40, X_train.shape[1]))
        X_selected = self.feature_selector.fit_transform(X_scaled, y_train)
        
        # Create ensemble model
        rf_model = RandomForestClassifier(
            n_estimators=300,
            max_depth=25,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        gb_model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
            subsample=0.8
        )
        
        # Voting classifier
        self.model = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('gb', gb_model)
            ],
            voting='soft',
            weights=[2, 1]
        )
        
        # Grid search optimization (optional, time-consuming)
        if use_grid_search:
            print("Performing grid search optimization...")
            param_grid = {
                'rf__n_estimators': [200, 300],
                'rf__max_depth': [20, 25],
                'gb__n_estimators': [150, 200],
                'gb__learning_rate': [0.05, 0.1]
            }
            grid_search = GridSearchCV(
                self.model, param_grid, cv=3, scoring='accuracy', n_jobs=-1, verbose=1
            )
            grid_search.fit(X_selected, y_train)
            self.model = grid_search.best_estimator_
            print(f"Best parameters: {grid_search.best_params_}")
        else:
            self.model.fit(X_selected, y_train)
        
        # Calculate feature importance
        self._calculate_feature_importance(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_selected)
        self.training_accuracy = accuracy_score(y_train, y_pred)
        
        print(f"Training completed! Accuracy: {self.training_accuracy:.2%}")
        print(f"Model version: {self.model_version}")
        
        self.is_trained = True
        return self.training_accuracy
    
    def predict(self, features_dict):
        """Predict if URL is phishing with confidence score"""
        if not self.is_trained:
            return self._rule_based_prediction(features_dict)
        
        try:
            # Extract features in correct order
            features_array = np.array([features_dict.get(f, 0) for f in self.feature_names])
            
            # Handle NaN or inf values
            features_array = np.nan_to_num(features_array, nan=0, posinf=0, neginf=0)
            features_array = features_array.reshape(1, -1)
            
            # Scale features
            features_scaled = self.scaler.transform(features_array)
            
            # Select best features
            features_selected = self.feature_selector.transform(features_scaled)
            
            # Predict
            prediction = self.model.predict(features_selected)[0]
            probabilities = self.model.predict_proba(features_selected)[0]
            confidence = probabilities[1] if prediction == 1 else probabilities[0]
            
            # Adjust confidence based on risk factors
            risk_factors = self._calculate_risk_factors(features_dict)
            confidence = min(confidence * (1 + (risk_factors / 200)), 0.99)
            
            return bool(prediction), float(confidence)
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return self._rule_based_prediction(features_dict)
    
    def predict_batch(self, features_list):
        """Predict multiple URLs in batch"""
        if not self.is_trained or not features_list:
            return [(self._rule_based_prediction(f))[0] for f in features_list]
        
        try:
            features_matrix = np.array([[f.get(feat, 0) for feat in self.feature_names] 
                                       for f in features_list])
            features_matrix = np.nan_to_num(features_matrix, nan=0)
            features_scaled = self.scaler.transform(features_matrix)
            features_selected = self.feature_selector.transform(features_scaled)
            
            predictions = self.model.predict(features_selected)
            probabilities = self.model.predict_proba(features_selected)
            
            results = []
            for i, pred in enumerate(predictions):
                confidence = probabilities[i][1] if pred == 1 else probabilities[i][0]
                results.append((bool(pred), float(confidence)))
            
            return results
        except Exception as e:
            print(f"Batch prediction error: {e}")
            return [(self._rule_based_prediction(f))[0] for f in features_list]
    
    def _rule_based_prediction(self, features_dict):
        """Fallback rule-based prediction when model not trained"""
        risk_score = 0
        
        # Weighted risk calculation
        if not features_dict.get('has_https', 0):
            risk_score += 25
        if features_dict.get('has_suspicious_keywords', 0):
            risk_score += 25
        if features_dict.get('has_ip_address', 0):
            risk_score += 30
        if features_dict.get('is_shortened', 0):
            risk_score += 20
        if features_dict.get('has_typosquatting', 0):
            risk_score += 25
        if features_dict.get('is_suspicious_tld', 0):
            risk_score += 15
        if features_dict.get('is_young_domain', 0):
            risk_score += 20
        if features_dict.get('has_many_subdomains', 0):
            risk_score += 15
        if features_dict.get('has_redirect', 0):
            risk_score += 10
        if features_dict.get('suspicious_keyword_count', 0) > 2:
            risk_score += 15
        
        risk_score = min(risk_score, 100)
        is_phishing = risk_score > 40
        confidence = 50 + (risk_score * 0.4) if is_phishing else 90 - (risk_score * 0.5)
        
        return is_phishing, min(confidence / 100, 0.99)
    
    def _calculate_risk_factors(self, features_dict):
        """Calculate risk factor score"""
        risk_score = 0
        for feature, weight in self.feature_weights.items():
            if features_dict.get(feature, 0):
                risk_score += weight * 10
        return min(risk_score, 100)
    
    def _calculate_feature_importance(self, X_train, y_train):
        """Calculate and store feature importance"""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        elif hasattr(self.model, 'estimators_'):
            # For voting classifier, average importances
            importances = np.zeros(len(self.feature_names))
            count = 0
            for name, estimator in self.model.named_estimators_.items():
                if hasattr(estimator, 'feature_importances_'):
                    importances += estimator.feature_importances_
                    count += 1
            if count > 0:
                importances /= count
        
        if 'importances' in locals():
            feature_imp = sorted(zip(self.feature_names, importances), 
                               key=lambda x: x[1], reverse=True)[:20]
            self.feature_importance = dict(feature_imp)
    
    def save_model(self, path='models/phishing_model.pkl'):
        """Save trained model to file"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'training_accuracy': self.training_accuracy,
            'feature_importance': self.feature_importance,
            'model_version': self.model_version,
            'training_date': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, path)
        print(f"Model saved to {path}")
        
        # Also save as JSON for easy access
        metadata_path = path.replace('.pkl', '_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump({
                'version': self.model_version,
                'accuracy': self.training_accuracy,
                'features_count': len(self.feature_names),
                'training_date': datetime.now().isoformat(),
                'top_features': self.feature_importance
            }, f, indent=2)
    
    def load_model(self, path='models/phishing_model.pkl'):
        """Load trained model from file"""
        if os.path.exists(path):
            try:
                model_data = joblib.load(path)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.feature_selector = model_data.get('feature_selector')
                self.feature_names = model_data['feature_names']
                self.is_trained = model_data['is_trained']
                self.training_accuracy = model_data.get('training_accuracy', 0)
                self.feature_importance = model_data.get('feature_importance', {})
                self.model_version = model_data.get('model_version', '1.0.0')
                print(f"Model loaded from {path} (v{self.model_version})")
                return True
            except Exception as e:
                print(f"Error loading model: {e}")
                return False
        return False


def generate_training_data(n_samples=20000):
    """Generate synthetic training data for model training"""
    print(f"Generating {n_samples} training samples...")
    np.random.seed(42)
    
    X = []
    y = []
    
    # Feature ranges for legitimate vs phishing sites
    for i in range(n_samples):
        # Determine if this sample is phishing (60% phishing for balanced training)
        is_phishing_sample = np.random.random() < 0.6
        
        features = {}
        
        # URL Structure Features
        if is_phishing_sample:
            features['url_length'] = np.random.randint(60, 250)
            features['hostname_length'] = np.random.randint(20, 70)
            features['path_length'] = np.random.randint(20, 150)
            features['query_length'] = np.random.randint(10, 100)
            features['num_dots'] = np.random.randint(3, 10)
            features['num_hyphens'] = np.random.randint(1, 6)
            features['num_underscores'] = np.random.randint(0, 4)
            features['num_slashes'] = np.random.randint(3, 10)
            features['num_question_marks'] = np.random.randint(0, 3)
            features['num_equals'] = np.random.randint(0, 5)
            features['num_ampersands'] = np.random.randint(0, 4)
            features['num_at_symbols'] = np.random.choice([0, 1], p=[0.9, 0.1])
            features['num_percent'] = np.random.randint(0, 3)
            features['num_colons'] = np.random.randint(0, 2)
            features['num_semicolons'] = np.random.randint(0, 2)
        else:
            features['url_length'] = np.random.randint(20, 80)
            features['hostname_length'] = np.random.randint(10, 30)
            features['path_length'] = np.random.randint(5, 50)
            features['query_length'] = np.random.randint(0, 30)
            features['num_dots'] = np.random.randint(1, 4)
            features['num_hyphens'] = np.random.randint(0, 2)
            features['num_underscores'] = np.random.randint(0, 1)
            features['num_slashes'] = np.random.randint(1, 4)
            features['num_question_marks'] = np.random.randint(0, 1)
            features['num_equals'] = np.random.randint(0, 2)
            features['num_ampersands'] = np.random.randint(0, 2)
            features['num_at_symbols'] = 0
            features['num_percent'] = 0
            features['num_colons'] = 0
            features['num_semicolons'] = 0
        
        # Character Composition
        features['num_digits'] = np.random.randint(0, 15) if is_phishing_sample else np.random.randint(0, 5)
        features['num_letters'] = np.random.randint(20, 100) if is_phishing_sample else np.random.randint(10, 50)
        features['digit_letter_ratio'] = features['num_digits'] / (features['num_letters'] + 1)
        features['entropy'] = np.random.uniform(3.5, 4.5) if is_phishing_sample else np.random.uniform(2.5, 3.5)
        
        # Domain Features
        features['domain_length'] = np.random.randint(8, 25) if is_phishing_sample else np.random.randint(5, 15)
        features['subdomain_count'] = np.random.randint(0, 5) if is_phishing_sample else np.random.randint(0, 2)
        features['subdomain_length'] = np.random.randint(0, 30) if is_phishing_sample else np.random.randint(0, 10)
        features['tld_length'] = np.random.choice([2, 3, 4])
        features['is_suspicious_tld'] = np.random.choice([0, 1], p=[0.6, 0.4]) if is_phishing_sample else 0
        features['has_many_subdomains'] = 1 if features['subdomain_count'] > 3 else 0
        features['has_typosquatting'] = np.random.choice([0, 1], p=[0.8, 0.2]) if is_phishing_sample else 0
        features['domain_age_days'] = np.random.randint(0, 30) if is_phishing_sample else np.random.randint(100, 3650)
        features['is_young_domain'] = 1 if features['domain_age_days'] < 30 else 0
        features['days_since_registration'] = features['domain_age_days']
        features['has_brand_in_subdomain'] = np.random.choice([0, 1], p=[0.9, 0.1]) if is_phishing_sample else 0
        
        # Security Features
        features['has_https'] = np.random.choice([0, 1], p=[0.4, 0.6]) if is_phishing_sample else 1
        features['suspicious_keyword_count'] = np.random.randint(0, 4) if is_phishing_sample else np.random.randint(0, 1)
        features['has_suspicious_keywords'] = 1 if features['suspicious_keyword_count'] > 0 else 0
        features['is_shortened'] = np.random.choice([0, 1], p=[0.85, 0.15]) if is_phishing_sample else 0
        features['has_redirect'] = np.random.choice([0, 1], p=[0.8, 0.2]) if is_phishing_sample else 0
        features['has_login_keyword'] = np.random.choice([0, 1], p=[0.7, 0.3]) if is_phishing_sample else 0
        features['multiple_slashes'] = 1 if features['num_slashes'] > 5 else 0
        features['has_ip_address'] = np.random.choice([0, 1], p=[0.95, 0.05]) if is_phishing_sample else 0
        features['has_hex_chars'] = np.random.choice([0, 1], p=[0.9, 0.1]) if is_phishing_sample else 0
        
        # Content Features
        features['has_forms'] = np.random.choice([0, 1], p=[0.5, 0.5]) if is_phishing_sample else 1
        features['has_password_field'] = np.random.choice([0, 1], p=[0.4, 0.6]) if is_phishing_sample else 0
        features['has_submit_button'] = np.random.choice([0, 1], p=[0.3, 0.7]) if is_phishing_sample else 1
        
        # Label (1 = phishing, 0 = legitimate)
        label = 1 if is_phishing_sample else 0
        
        # Convert to array in correct order
        feature_names = [
            'url_length', 'hostname_length', 'path_length', 'query_length',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equals', 'num_ampersands', 'num_at_symbols',
            'num_percent', 'num_colons', 'num_semicolons',
            'num_digits', 'num_letters', 'digit_letter_ratio', 'entropy',
            'domain_length', 'subdomain_count', 'subdomain_length', 'tld_length',
            'is_suspicious_tld', 'has_many_subdomains', 'has_typosquatting',
            'domain_age_days', 'is_young_domain', 'days_since_registration',
            'has_brand_in_subdomain',
            'has_https', 'suspicious_keyword_count', 'has_suspicious_keywords',
            'is_shortened', 'has_redirect', 'has_login_keyword', 'multiple_slashes',
            'has_ip_address', 'has_hex_chars',
            'has_forms', 'has_password_field', 'has_submit_button'
        ]
        
        X.append([features[f] for f in feature_names])
        y.append(label)
    
    X = np.array(X)
    y = np.array(y)
    
    # Add some noise to prevent overfitting
    noise = np.random.normal(0, 0.01, X.shape)
    X = X + noise
    
    print(f"Generated {len(X)} samples with {sum(y)} phishing ({sum(y)/len(y)*100:.1f}%)")
    return X, y


# Initialize global detector
detector = AdvancedPhishingDetector()

# Try to load existing model
if not detector.load_model('models/phishing_model.pkl'):
    print("No existing model found. Training new model...")
    X_train, y_train = generate_training_data(20000)
    
    # Split for validation
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42)
    
    # Train model
    accuracy = detector.train(X_train, y_train, use_grid_search=False)
    
    # Validate
    X_val_scaled = detector.scaler.transform(X_val)
    X_val_selected = detector.feature_selector.transform(X_val_scaled) if detector.feature_selector else X_val_scaled
    val_predictions = detector.model.predict(X_val_selected)
    val_accuracy = accuracy_score(y_val, val_predictions)
    
    print(f"Validation accuracy: {val_accuracy:.2%}")
    
    # Save model
    detector.save_model('models/phishing_model.pkl')
    print("Model training and saving completed!")