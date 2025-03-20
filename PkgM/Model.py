from flask import Blueprint, jsonify, request,Flask
from Prediction_model import classify_url
from URL_extractor import extract_features, extract_urls_from_text

model = Blueprint("PhiModel", __name__)
app = Flask(__name__)
@model.route("/phishing", methods=["POST"])
def phishing_detector():

    try:
        # Validate input
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'Request body is required',
                'status': 400
            }), 400

        # Check if either URL or message is provided
        url = data.get('url', '').strip()
        message = data.get('message', '').strip()

        if not url and not message:
            return jsonify({
                'error': 'Either URL or text message is required',
                'status': 400
            }), 400

        results = []

        # Process direct URL if provided
        if url:
            features = extract_features(url)
            result = classify_url(features)
            results.append({
                'url': url,
                'prediction': result['status'],
                'confidence': result['confidence'],
                'detected_features': result['active_features']
            })

        # Process URLs from message if provided
        if message:
            urls = extract_urls_from_text(message)
            for msg_url in urls:
                if msg_url != url:  # Avoid duplicate analysis
                    features = extract_features(msg_url)
                    result = classify_url(features)
                    results.append({
                        'url': msg_url,
                        'prediction': result['status'],
                        'confidence': result['confidence'],
                        'detected_features': result['active_features']
                    })

        return jsonify({
            'status': 200,
            'urls_analyzed': len(results),
            'results': results
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 500
        }), 500
    
app.register_blueprint(model)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)