7
import os

from flask import Flask, jsonify, request
import hmac


app = Flask(__name__)
latest_stats = None

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
    if latest_stats is None:
        return jsonify({
            "status": "waiting",
            "message": "Waiting for real bot statistics"
        }), 503

    return jsonify(latest_stats)
  
@app.after_request
def allow_dashboard(response):
    response.headers["Access-Control-Allow-Origin"] = "https://fastchangearz.github.io"
    return response

@app.route("/sync-stats", methods=["POST"])
def sync_stats():
    secret = os.environ.get("IRAN_CHANGE_SYNC_KEY")

    if not secret:
        return jsonify({"error": "Server not configured"}), 503

    supplied = request.headers.get("X-Sync-Key", "")

    if not hmac.compare_digest(supplied, secret):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    keys = ("total_ads", "active_ads", "closed_ads")

    if any(
        type(data.get(key)) is not int or data[key] < 0
        for key in keys
    ):
        return jsonify({"error": "Invalid statistics"}), 400

    if data["active_ads"] + data["closed_ads"] != data["total_ads"]:
        return jsonify({"error": "Inconsistent statistics"}), 400

    global latest_stats

    latest_stats = {
        "total_ads": data["total_ads"],
        "active_ads": data["active_ads"],
        "closed_ads": data["closed_ads"]
    }

    return jsonify({"status": "saved"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
