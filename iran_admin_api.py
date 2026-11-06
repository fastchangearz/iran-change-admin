import os
import hmac
from flask import Flask, jsonify, request

app = Flask(__name__)

latest_stats = None
latest_ads = []
latest_offers = []
latest_conversations = []


@app.route("/")
def home():
    return jsonify({
        "project": "Iran Change Admin API",
        "status": "online",
        "message": "Server is running"
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.after_request
def allow_dashboard(response):
    response.headers["Access-Control-Allow-Origin"] = (
        "https://fastchangearz.github.io"
    )
    return response


@app.route("/status")
def status():
    if latest_stats is None:
        return jsonify({
            "status": "waiting",
            "message": "Waiting for real bot statistics"
        }), 503

    return jsonify(latest_stats)


@app.route("/sync-stats", methods=["POST"])
def sync_stats():
    global latest_stats

    secret = os.environ.get("IRAN_CHANGE_SYNC_KEY")
    supplied = request.headers.get("X-Sync-Key", "")

    if not secret:
        return jsonify({"error": "Server not configured"}), 503

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

    latest_stats = {
        "total_ads": data["total_ads"],
        "active_ads": data["active_ads"],
        "closed_ads": data["closed_ads"]
    }

    return jsonify({"status": "saved"})


@app.route("/ads")
def get_ads():
    return jsonify({
        "ads": latest_ads,
        "count": len(latest_ads)
    })


@app.route("/sync-ads", methods=["POST"])
def sync_ads():
    global latest_ads

    secret = os.environ.get("IRAN_CHANGE_SYNC_KEY")
    supplied = request.headers.get("X-Sync-Key", "")

    if not secret:
        return jsonify({"error": "Server not configured"}), 503

    if not hmac.compare_digest(supplied, secret):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    ads = data.get("ads")

    if not isinstance(ads, list):
        return jsonify({"error": "Invalid ads"}), 400

    latest_ads = ads

    return jsonify({
        "status": "saved",
        "count": len(latest_ads)
    })


@app.route("/offers")
def get_offers():
    return jsonify({
        "offers": latest_offers,
        "count": len(latest_offers)
    })


@app.route("/sync-offers", methods=["POST"])
def sync_offers():
    global latest_offers

    secret = os.environ.get("IRAN_CHANGE_SYNC_KEY")
    supplied = request.headers.get("X-Sync-Key", "")

    if not secret:
        return jsonify({"error": "Server not configured"}), 503

    if not hmac.compare_digest(supplied, secret):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    offers = data.get("offers")

    if not isinstance(offers, list):
        return jsonify({"error": "Invalid offers"}), 400

    allowed = {
        "offer_id", "ad_id", "proposed_price",
        "status", "created_at"
    }

    cleaned = []

    for offer in offers:
        if not isinstance(offer, dict):
            return jsonify({"error": "Invalid offer item"}), 400

        cleaned.append({
            key: offer.get(key)
            for key in allowed
        })

    latest_offers = cleaned

    return jsonify({
        "status": "saved",
        "count": len(latest_offers)
    })


@app.route("/conversations")
def get_conversations():
    return jsonify({
        "conversations": latest_conversations,
        "count": len(latest_conversations)
    })


@app.route("/sync-conversations", methods=["POST"])
def sync_conversations():
    global latest_conversations

    secret = os.environ.get("IRAN_CHANGE_SYNC_KEY")
    supplied = request.headers.get("X-Sync-Key", "")

    if not secret:
        return jsonify({"error": "Server not configured"}), 503

    if not hmac.compare_digest(supplied, secret):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    conversations = data.get("conversations")

    if not isinstance(conversations, list):
        return jsonify({"error": "Invalid conversations"}), 400

    cleaned = []

    for item in conversations:
        if not isinstance(item, dict):
            return jsonify({"error": "Invalid conversation item"}), 400

        conversation_id = item.get("conversation_id")
        ad_id = item.get("ad_id")
        status = item.get("status")
        created_at = item.get("created_at")
        updated_at = item.get("updated_at")

        if type(conversation_id) is not int:
            return jsonify({"error": "Invalid conversation ID"}), 400

        if type(ad_id) is not int:
            return jsonify({"error": "Invalid ad ID"}), 400

        if not isinstance(status, str):
            return jsonify({"error": "Invalid status"}), 400

        cleaned.append({
            "conversation_id": conversation_id,
            "ad_id": ad_id,
            "status": status,
            "created_at": str(created_at or ""),
            "updated_at": str(updated_at or "")
        })

    latest_conversations = cleaned

    return jsonify({
        "status": "saved",
        "count": len(latest_conversations)
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
