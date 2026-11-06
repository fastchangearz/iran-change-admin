import os
import hmac
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

latest_stats = None
latest_ads = []
latest_offers = []
latest_conversations = []
latest_deals = []

TABLES = {
    "ads": ("iran_ads", "ad_id"),
    "offers": ("iran_offers", "offer_id"),
    "conversations": ("iran_conversations", "conversation_id"),
    "deals": ("iran_deals", "ad_id,offer_id")
}

FIELDS = {
    "ads": (
        "ad_id", "trade_type", "currency", "amount",
        "price", "method", "country", "status",
        "created_at"
    ),
    "offers": (
        "offer_id", "ad_id", "proposed_price",
        "status", "created_at"
    ),
    "conversations": (
        "conversation_id", "ad_id", "status",
        "created_at", "updated_at"
    ),
    "deals": (
        "ad_id", "offer_id", "owner_confirmed",
        "proposer_confirmed", "cancel_requested",
        "state", "deadline", "created_at"
    )
}


def supabase_config():
    url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SUPABASE_SECRET_KEY", "")

    if not url or not key:
        raise RuntimeError("Supabase is not configured")

    return url + "/rest/v1", {
        "apikey": key,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }


def read_supabase(table):
    base, headers = supabase_config()
    result = []
    offset = 0
    page_size = 1000

    while True:
        response = requests.get(
            base + "/" + table,
            headers=headers,
            params={
                "select": "*",
                "limit": page_size,
                "offset": offset
            },
            timeout=25
        )
        response.raise_for_status()
        rows = response.json()

        if not isinstance(rows, list):
            raise ValueError("Invalid database response")

        result.extend(rows)

        if len(rows) < page_size:
            break

        offset += page_size

    return result


def save_supabase(table, rows, conflict):
    if not rows:
        return

    base, headers = supabase_config()
    headers["Prefer"] = (
        "resolution=merge-duplicates,return=minimal"
    )

    for start in range(0, len(rows), 100):
        batch = rows[start:start + 100]

        response = requests.post(
            base + "/" + table,
            params={"on_conflict": conflict},
            headers=headers,
            json=batch,
            timeout=30
        )
        response.raise_for_status()


def authorized():
    secret = os.environ.get("IRAN_CHANGE_SYNC_KEY", "")
    supplied = request.headers.get("X-Sync-Key", "")

    return bool(secret) and hmac.compare_digest(
        supplied, secret
    )


def clean_rows(section, rows):
    if not isinstance(rows, list):
        raise ValueError("Invalid list")

    fields = FIELDS[section]
    cleaned = []

    for item in rows:
        if not isinstance(item, dict):
            raise ValueError("Invalid item")

        row = {
            field: item[field]
            for field in fields
            if field in item
        }

        if section == "deals":
            for field in ("ad_id", "offer_id"):
                if type(row.get(field)) is not int:
                    raise ValueError("Invalid deal ID")

            for field in (
                "owner_confirmed", "proposer_confirmed"
            ):
                value = row.get(field)
                if type(value) is not int or value not in (0, 1):
                    raise ValueError("Invalid confirmation")

            if not isinstance(row.get("state"), str):
                raise ValueError("Invalid deal state")

            # Database column is BIGINT.
            # Store cancellation status as 0 or 1.
            row["cancel_requested"] = int(
                bool(item.get("cancel_requested", False))
            )

            row["deadline"] = str(
                item.get("deadline") or ""
            )
            row["created_at"] = str(
                item.get("created_at") or ""
            )

        if section == "conversations":
            for field in ("conversation_id", "ad_id"):
                if type(row.get(field)) is not int:
                    raise ValueError("Invalid conversation ID")

            if not isinstance(row.get("status"), str):
                raise ValueError("Invalid conversation status")

            row["created_at"] = str(
                item.get("created_at") or ""
            )
            row["updated_at"] = str(
                item.get("updated_at") or ""
            )

        cleaned.append(row)

    return cleaned


@app.after_request
def allow_dashboard(response):
    response.headers["Access-Control-Allow-Origin"] = (
        "https://fastchangearz.github.io"
    )
    return response


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


@app.route("/status")
def status():
    if latest_stats is not None:
        return jsonify(latest_stats)

    try:
        ads = read_supabase("iran_ads")
        total = len(ads)
        active = sum(
            1 for ad in ads
            if str(ad.get("status", "")).lower()
            in ("active", "published")
        )
        return jsonify({
            "total_ads": total,
            "active_ads": active,
            "closed_ads": total - active
        })
    except (requests.RequestException, RuntimeError, ValueError):
        app.logger.exception("Statistics unavailable")
        return jsonify({
            "status": "waiting",
            "message": "Database temporarily unavailable"
        }), 503


@app.route("/sync-stats", methods=["POST"])
def sync_stats():
    global latest_stats

    if not authorized():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    keys = ("total_ads", "active_ads", "closed_ads")

    if any(
        type(data.get(key)) is not int or data[key] < 0
        for key in keys
    ):
        return jsonify({
            "error": "Invalid statistics"
        }), 400

    if (
        data["active_ads"] + data["closed_ads"]
        != data["total_ads"]
    ):
        return jsonify({
            "error": "Inconsistent statistics"
        }), 400

    latest_stats = {
        key: data[key] for key in keys
    }

    return jsonify({"status": "saved"})


def get_section(section):
    table, conflict = TABLES[section]

    try:
        rows = read_supabase(table)

        if section == "deals":
            for row in rows:
                row["cancel_requested"] = bool(
                    row.get("cancel_requested")
                )

        return jsonify({
            section: rows,
            "count": len(rows)
        })

    except (requests.RequestException, RuntimeError, ValueError):
        app.logger.exception(
            "Supabase read failed: %s", section
        )
        return jsonify({
            "error": "Database temporarily unavailable"
        }), 503


def sync_section(section):
    global latest_ads
    global latest_offers
    global latest_conversations
    global latest_deals

    if not authorized():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    if not isinstance(data.get(section), list):
        return jsonify({
            "error": "Invalid " + section
        }), 400

    try:
        rows = clean_rows(section, data[section])
    except (ValueError, TypeError):
        return jsonify({
            "error": "Invalid data"
        }), 400

    table, conflict = TABLES[section]

    try:
        save_supabase(table, rows, conflict)
    except (requests.RequestException, RuntimeError):
        app.logger.exception(
            "Supabase save failed: %s", section
        )
        return jsonify({
            "error": "Database save failed"
        }), 503

    if section == "ads":
        latest_ads = rows
    elif section == "offers":
        latest_offers = rows
    elif section == "conversations":
        latest_conversations = rows
    elif section == "deals":
        latest_deals = rows

    return jsonify({
        "status": "saved",
        "count": len(rows)
    })


@app.route("/ads")
def get_ads():
    return get_section("ads")


@app.route("/sync-ads", methods=["POST"])
def sync_ads():
    return sync_section("ads")


@app.route("/offers")
def get_offers():
    return get_section("offers")


@app.route("/sync-offers", methods=["POST"])
def sync_offers():
    return sync_section("offers")


@app.route("/conversations")
def get_conversations():
    return get_section("conversations")


@app.route("/sync-conversations", methods=["POST"])
def sync_conversations():
    return sync_section("conversations")


@app.route("/deals")
def get_deals():
    return get_section("deals")


@app.route("/sync-deals", methods=["POST"])
def sync_deals():
    return sync_section("deals")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
