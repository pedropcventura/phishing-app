from flask import Flask, request, jsonify
from phishing import normalize_url, extract_features
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/api/analyze", methods=['POST'])
def analyze():
    print("base")
    body = request.get_json(force=True)
    url_raw = body.get('url')
    if not url_raw:
        return jsonify({'error': 'URL é obrigatória'}), 400
    
    url = normalize_url(url_raw)
    features = extract_features(url)
    return jsonify({'url': url, 'features': features})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)