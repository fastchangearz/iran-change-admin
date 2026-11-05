7
import os
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "project": "Iran Change Admin API",
        "status": "online",
        "message": "Server is running"
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "ok"
    })


@app.route("/status")
def status():
    return jsonify({
        "total_ads": 50,
        "active_ads": 41,
        "closed_ads": 9
    })
  
@app.after_request
def allow_dashboard(response):
    response.headers["Access-Control-Allow-Origin"] = "https://fastchangearz.github.io"
    return response

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
