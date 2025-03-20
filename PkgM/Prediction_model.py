import joblib
import os
path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'PkgM', 'phishing_model.joblib')
def classify_url(features):

    try:
        # Load model
        model = joblib.load(path)
        
        # Make prediction
        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0][1] * 100
        
        # Get active features
        active_features = {
            feature: value for feature, value 
            in features.iloc[0].items() if value > 0
        }
        
        return {
            'status': 'PHISHING' if prediction else 'LEGITIMATE',
            'confidence': f"{confidence:.1f}%",
            'active_features': active_features
        }
        
    except Exception as e:
        raise Exception(f"Prediction error: {str(e)}")