
import os
import hmac
import logging
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request


app = Flask(__name__)

latest_stats = None
latest_ads = []
latest_offers = []
latest_conversations = []
latest_deals = []


TABLES = {
    'ads': ('iran_ads', 'ad_id'),
    'offers': ('iran_offers', 'offer_id'),
    'conversations': ('iran_conversations', 'conversation_id'),
    'deals': ('iran_deals', 'ad_id,offer_id'),
}


FIELDS = {
    'ads': (
        'ad_id',
        'trade_type',
        'currency',
        'amount',
        'price',
        'method',
        'country',
        'status',
        'created_at'
    ),
    'offers': (
        'offer_id',
        'ad_id',
        'proposed_price',
        'status',
        'created_at'
    ),
    'conversations': (
        'conversation_id',
        'ad_id',
        'status',
        'created_at',
        'updated_at'
    ),
    'deals': (
        'ad_id',
        'offer_id',
        'owner_confirmed',
        'proposer_confirmed',
        'cancel_requested',
        'state',
        'deadline',
        'created_at'
    ),
}


# ==========================================
# Supabase Connection
# ==========================================

def supabase_config():
    url = os.environ.get(
        'SUPABASE_URL', ''
    ).rstrip('/')

    key = os.environ.get(
        'SUPABASE_SERVICE_ROLE_KEY', ''
    )

    if not url or not key:
        raise RuntimeError(
            'Supabase is not configured'
        )

    return url + '/rest/v1', {
        'apikey': key,
        'Authorization': 'Bearer ' + key,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }


def db_request(
    method,
    table,
    params=None,
    payload=None,
    prefer=None
):
    base, headers = supabase_config()

    if prefer:
        headers['Prefer'] = prefer

    response = requests.request(
        method,
        base + '/' + table,
        headers=headers,
        params=params,
        json=payload,
        timeout=25,
    )

    response.raise_for_status()

    if not response.content:
        return []

    return response.json()


def read_supabase(table):
    result = []
    offset = 0

    while True:
        rows = db_request(
            'GET',
            table,
            {
                'select': '*',
                'limit': 1000,
                'offset': offset
            }
        )

        if not isinstance(rows, list):
            raise ValueError(
                'Invalid database response'
            )

        result.extend(rows)

        if len(rows) < 1000:
            return result

        offset += 1000


def save_supabase(table, rows, conflict):
    for i in range(0, len(rows), 100):
        db_request(
            'POST',
            table,
            {'on_conflict': conflict},
            rows[i:i + 100],
            'resolution=merge-duplicates,return=minimal'
        )


# ==========================================
# Authentication
# ==========================================

def authorized():
    secret = os.environ.get(
        'IRAN_CHANGE_SYNC_KEY', ''
    )

    supplied = request.headers.get(
        'X-Sync-Key', ''
    )

    return bool(secret) and hmac.compare_digest(
        supplied,
        secret
    )


def admin_authorized():
    secret = os.environ.get(
        'IRAN_CHANGE_ADMIN_KEY', ''
    )

    supplied = request.headers.get(
        'X-Admin-Key', ''
    )

    return bool(secret) and hmac.compare_digest(
        supplied,
        secret
    )


# ==========================================
# Data Validation
# ==========================================

def clean_rows(section, rows):
    if not isinstance(rows, list):
        raise ValueError('Invalid list')

    cleaned = []

    for item in rows:
        if not isinstance(item, dict):
            raise ValueError('Invalid item')

        row = {
            f: item[f]
            for f in FIELDS[section]
            if f in item
        }

        if section == 'deals':
            for f in ('ad_id', 'offer_id'):
                if type(row.get(f)) is not int:
                    raise ValueError('Invalid deal ID')

            for f in (
                'owner_confirmed',
                'proposer_confirmed'
            ):
                if (
                    type(row.get(f)) is not int
                    or row[f] not in (0, 1)
                ):
                    raise ValueError(
                        'Invalid confirmation'
                    )

            if not isinstance(
                row.get('state'), str
            ):
                raise ValueError(
                    'Invalid deal state'
                )

            row['cancel_requested'] = int(
                bool(
                    item.get(
                        'cancel_requested',
                        False
                    )
                )
            )

            row['deadline'] = str(
                item.get('deadline') or ''
            )

            row['created_at'] = str(
                item.get('created_at') or ''
            )

        if section == 'conversations':
            for f in (
                'conversation_id',
                'ad_id'
            ):
                if type(row.get(f)) is not int:
                    raise ValueError(
                        'Invalid conversation ID'
                    )

            if not isinstance(
                row.get('status'), str
            ):
                raise ValueError(
                    'Invalid conversation status'
                )

            row['created_at'] = str(
                item.get('created_at') or ''
            )

            row['updated_at'] = str(
                item.get('updated_at') or ''
            )

        cleaned.append(row)

    return cleaned


# ==========================================
# Dashboard CORS
# ==========================================

@app.after_request
def allow_dashboard(response):
    response.headers[
        'Access-Control-Allow-Origin'
    ] = 'https://fastchangearz.github.io'

    response.headers[
        'Access-Control-Allow-Headers'
    ] = 'Content-Type, X-Admin-Key'

    response.headers[
        'Access-Control-Allow-Methods'
    ] = 'GET, POST, OPTIONS'

    return response


# ==========================================
# General Routes
# ==========================================

@app.route('/')
def home():
    return jsonify({
        'project': 'Iran Change Admin API',
        'status': 'online',
        'message': 'Server is running'
    })


@app.route('/health')
def health():
    return jsonify({
        'status': 'ok'
    })


@app.route('/status')
def status():
    if latest_stats is not None:
        return jsonify(latest_stats)

    try:
        ads = read_supabase('iran_ads')

        active = sum(
            1
            for a in ads
            if str(
                a.get('status', '')
            ).lower() in (
                'active',
                'published'
            )
        )

        return jsonify({
            'total_ads': len(ads),
            'active_ads': active,
            'closed_ads': len(ads) - active
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError
    ):
        app.logger.exception(
            'Statistics unavailable'
        )

        return jsonify({
            'status': 'waiting',
            'message': (
                'Database temporarily unavailable'
            )
        }), 503


# ==========================================
# Sync Statistics
# ==========================================

@app.route(
    '/sync-stats',
    methods=['POST']
)
def sync_stats():
    global latest_stats

    if not authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            'error': 'Invalid JSON'
        }), 400

    keys = (
        'total_ads',
        'active_ads',
        'closed_ads'
    )

    if any(
        type(data.get(k)) is not int
        or data[k] < 0
        for k in keys
    ):
        return jsonify({
            'error': 'Invalid statistics'
        }), 400

    if (
        data['active_ads']
        + data['closed_ads']
        != data['total_ads']
    ):
        return jsonify({
            'error': 'Inconsistent statistics'
        }), 400

    latest_stats = {
        k: data[k]
        for k in keys
    }

    return jsonify({
        'status': 'saved'
    })


# ==========================================
# Read and Sync Sections
# ==========================================

def get_section(section):
    try:
        rows = read_supabase(
            TABLES[section][0]
        )

        if section == 'deals':
            for row in rows:
                row['cancel_requested'] = bool(
                    row.get('cancel_requested')
                )

        return jsonify({
            section: rows,
            'count': len(rows)
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError
    ):
        app.logger.exception(
            'Supabase read failed: %s',
            section
        )

        return jsonify({
            'error': (
                'Database temporarily unavailable'
            )
        }), 503


def sync_section(section):
    global latest_ads
    global latest_offers
    global latest_conversations
    global latest_deals

    if not authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    data = request.get_json(
        silent=True
    )

    if (
        not isinstance(data, dict)
        or not isinstance(
            data.get(section), list
        )
    ):
        return jsonify({
            'error': 'Invalid JSON'
        }), 400

    try:
        rows = clean_rows(
            section,
            data[section]
        )

    except (
        ValueError,
        TypeError
    ):
        return jsonify({
            'error': 'Invalid data'
        }), 400

    table, conflict = TABLES[section]

    try:
        save_supabase(
            table,
            rows,
            conflict
        )

    except (
        requests.RequestException,
        RuntimeError
    ):
        app.logger.exception(
            'Supabase save failed: %s',
            section
        )

        return jsonify({
            'error': 'Database save failed'
        }), 503

    if section == 'ads':
        latest_ads = rows

    elif section == 'offers':
        latest_offers = rows

    elif section == 'conversations':
        latest_conversations = rows

    elif section == 'deals':
        latest_deals = rows

    return jsonify({
        'status': 'saved',
        'count': len(rows)
    })


# ==========================================
# Ads
# ==========================================

@app.route('/ads')
def get_ads():
    return get_section('ads')


@app.route(
    '/sync-ads',
    methods=['POST']
)
def sync_ads():
    return sync_section('ads')


# ==========================================
# Offers
# ==========================================

@app.route('/offers')
def get_offers():
    return get_section('offers')


@app.route(
    '/sync-offers',
    methods=['POST']
)
def sync_offers():
    return sync_section('offers')


# ==========================================
# Conversations
# ==========================================

@app.route('/conversations')
def get_conversations():
    return get_section(
        'conversations'
    )


@app.route(
    '/sync-conversations',
    methods=['POST']
)
def sync_conversations():
    return sync_section(
        'conversations'
    )


# ==========================================
# Deals
# ==========================================

@app.route('/deals')
def get_deals():
    return get_section('deals')


@app.route(
    '/sync-deals',
    methods=['POST']
)
def sync_deals():
    return sync_section('deals')


# ==========================================
# Admin Verification
# ==========================================

@app.route(
    '/admin/verify',
    methods=['POST', 'OPTIONS']
)
def admin_verify():
    if request.method == 'OPTIONS':
        return '', 204

    if not admin_authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    return jsonify({
        'status': 'authorized'
    })


# ==========================================
# Admin Actions
# ==========================================

@app.route(
    '/admin/actions',
    methods=['GET', 'OPTIONS']
)
def admin_actions():
    if request.method == 'OPTIONS':
        return '', 204

    if not admin_authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    try:
        rows = read_supabase(
            'iran_admin_actions'
        )

        rows.sort(
            key=lambda r: r.get(
                'id', 0
            ),
            reverse=True
        )

        return jsonify({
            'actions': rows,
            'count': len(rows)
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError
    ):
        app.logger.exception(
            'Admin actions unavailable'
        )

        return jsonify({
            'error': (
                'Database temporarily unavailable'
            )
        }), 503


# ==========================================
# Admin Deal Action
# ==========================================

@app.route(
    '/admin/deal-action',
    methods=['POST', 'OPTIONS']
)
def admin_deal_action():
    if request.method == 'OPTIONS':
        return '', 204

    if not admin_authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            'error': 'Invalid JSON'
        }), 400

    ad_id = data.get('ad_id')
    offer_id = data.get('offer_id')
    action = data.get('action')

    reason = str(
        data.get('reason') or ''
    ).strip()

    if (
        type(ad_id) is not int
        or type(offer_id) is not int
        or ad_id < 2512
        or offer_id <= 0
        or action not in (
            'review',
            'cancel',
            'complete',
            'reopen'
        )
    ):
        return jsonify({
            'error': 'Invalid action'
        }), 400

    if (
        action == 'cancel'
        and len(reason) < 3
    ):
        return jsonify({
            'error': (
                'Cancellation reason required'
            )
        }), 400

    if len(reason) > 1000:
        return jsonify({
            'error': 'Reason too long'
        }), 400

    try:
        matches = db_request(
            'GET',
            'iran_deals',
            {
                'select': '*',
                'ad_id': 'eq.' + str(ad_id),
                'offer_id': 'eq.' + str(offer_id),
                'limit': 1,
            }
        )

        if not matches:
            return jsonify({
                'error': 'Deal not found'
            }), 404

        deal = matches[0]

        state = str(
            deal.get('state') or ''
        ).lower()

        if state in (
            'completed',
            'cancelled'
        ):
            return jsonify({
                'error': (
                    'Final deal is read-only'
                )
            }), 409

        if (
            action == 'reopen'
            and state != 'admin_review'
        ):
            return jsonify({
                'error': (
                    'Only a deal under review '
                    'can be reopened'
                )
            }), 409

        if (
            action == 'review'
            and state == 'admin_review'
        ):
            return jsonify({
                'error': (
                    'Already under review'
                )
            }), 409

        if action == 'complete':
            owner_confirmed = int(
                deal.get(
                    'owner_confirmed'
                ) or 0
            )

            proposer_confirmed = int(
                deal.get(
                    'proposer_confirmed'
                ) or 0
            )

            if not (
                owner_confirmed == 1
                and proposer_confirmed == 1
            ):
                return jsonify({
                    'error': (
                        'Both parties must confirm'
                    )
                }), 409

        command = {
            'ad_id': ad_id,
            'offer_id': offer_id,
            'action': action,
            'reason': reason,
            'expected_state': state,
            'status': 'pending',
        }

        try:
            saved = db_request(
                'POST',
                'iran_admin_commands',
                payload=[command],
                prefer='return=representation'
            )

        except requests.HTTPError as exc:
            if (
                exc.response is not None
                and exc.response.status_code == 409
            ):
                return jsonify({
                    'error': (
                        'A command is already '
                        'pending for this ad'
                    )
                }), 409

            raise

        if (
            not isinstance(saved, list)
            or not saved
        ):
            raise ValueError(
                'Command was not returned '
                'by database'
            )

        return jsonify({
            'status': 'pending',
            'message': (
                'Command queued for Telegram bot'
            ),
            'command_id': saved[0]['id'],
            'ad_id': ad_id,
            'offer_id': offer_id,
        }), 202

    except (
        requests.RequestException,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError
    ):
        app.logger.exception(
            'Admin command creation failed'
        )

        return jsonify({
            'error': (
                'Database operation failed'
            )
        }), 503


# ==========================================
# Telegram Bot - Admin Command Connection
# ==========================================

@app.route(
    '/bot/commands',
    methods=['GET']
)
def bot_commands():
    if not authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    try:
        rows = db_request(
            'GET',
            'iran_admin_commands',
            {
                'select': (
                    'id,ad_id,offer_id,action,'
                    'reason,expected_state,status'
                ),
                'status': 'eq.pending',
                'order': 'id.asc',
                'limit': 20
            }
        )

        return jsonify({
            'commands': rows
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError
    ):
        app.logger.exception(
            'Bot command polling failed'
        )

        return jsonify({
            'error': (
                'Database unavailable'
            )
        }), 503


# ==========================================
# Bot Command Acknowledgement
# ==========================================

@app.route(
    '/bot/commands/<int:command_id>/ack',
    methods=['POST']
)
def bot_command_ack(command_id):
    if not authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return jsonify({
            'error': 'Invalid JSON'
        }), 400

    if data.get('status') not in (
        'done',
        'failed'
    ):
        return jsonify({
            'error': 'Invalid status'
        }), 400

    error = str(
        data.get('error') or ''
    )[:500]

    try:
        matches = db_request(
            'GET',
            'iran_admin_commands',
            {
                'select': 'id,status',
                'id': 'eq.' + str(command_id),
                'limit': 1
            }
        )

        if not matches:
            return jsonify({
                'error': 'Command not found'
            }), 404

        if (
            matches[0]['status']
            != 'pending'
        ):
            return jsonify({
                'status': (
                    matches[0]['status']
                ),
                'already_acknowledged': True
            })

        db_request(
            'PATCH',
            'iran_admin_commands',
            {
                'id': 'eq.' + str(command_id),
                'status': 'eq.pending'
            },
            {
                'status': data['status'],
                'error': error,
                'finished_at': datetime.now(
                    timezone.utc
                ).isoformat()
            },
            'return=minimal'
        )

        return jsonify({
            'status': data['status']
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError,
        KeyError
    ):
        app.logger.exception(
            'Bot command acknowledgement failed'
        )

        return jsonify({
            'error': (
                'Database unavailable'
            )
        }), 503


# ==========================================
# Admin Support Center
# ==========================================

@app.route(
    '/admin/support/messages',
    methods=['GET', 'OPTIONS']
)
def admin_support_messages():
    if request.method == 'OPTIONS':
        return '', 204

    if not admin_authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    try:
        rows = read_supabase(
            'iran_support_messages'
        )

        rows.sort(
            key=lambda r: r.get('id', 0),
            reverse=True
        )

        return jsonify({
            'messages': rows,
            'count': len(rows)
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError
    ):
        app.logger.exception(
            'Support messages unavailable'
        )

        return jsonify({
            'error': 'Database unavailable'
        }), 503


@app.route(
    '/admin/support/reply',
    methods=['POST', 'OPTIONS']
)
def admin_support_reply():
    if request.method == 'OPTIONS':
        return '', 204

    if not admin_authorized():
        return jsonify({
            'error': 'Unauthorized'
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            'error': 'Invalid JSON'
        }), 400

    user_id = data.get('user_id')
    body = data.get('body')

    if (
        type(user_id) is not int
        or user_id <= 0
        or not isinstance(body, str)
        or not body.strip()
        or len(body) > 4000
    ):
        return jsonify({
            'error': 'Invalid recipient or message'
        }), 400

    try:
        saved = db_request(
            'POST',
            'iran_support_outbox',
            payload=[{
                'user_id': user_id,
                'body': body.strip(),
                'status': 'pending'
            }],
            prefer='return=representation'
        )

        if not isinstance(saved, list) or not saved:
            raise ValueError(
                'Reply was not saved'
            )

        return jsonify({
            'status': 'pending',
            'message': 'Reply queued',
            'reply_id': saved[0]['id']
        }), 202

    except (
        requests.RequestException,
        RuntimeError,
        ValueError,
        KeyError
    ):
        app.logger.exception(
            'Support reply failed'
        )

        return jsonify({
            'error': 'Database save failed'
        }), 503
# Add this block to app.py before the Start Server section.
# Uses existing app, authorized, db_request and datetime/timezone.

@app.route('/bot/support/incoming', methods=['POST'])
def bot_support_incoming():
    if not authorized():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON'}), 400
    uid = data.get('user_id')
    mid = data.get('telegram_message_id')
    kind = data.get('kind')
    body = data.get('body') or ''
    if (type(uid) is not int or uid <= 0 or type(mid) is not int or mid <= 0
            or kind not in ('text', 'photo', 'document')
            or not isinstance(body, str) or len(body) > 4000):
        return jsonify({'error': 'Invalid message'}), 400
    fid = data.get('file_id')
    if kind != 'text' and (not isinstance(fid, str) or not fid):
        return jsonify({'error': 'Missing file_id'}), 400
    try:
        # Telegram updates may be retried: avoid duplicate records.
        found = db_request('GET', 'iran_support_messages', {
            'select': 'id', 'user_id': 'eq.' + str(uid),
            'telegram_message_id': 'eq.' + str(mid),
            'direction': 'eq.incoming', 'limit': 1
        })
        if found:
            return jsonify({'status': 'already_saved', 'id': found[0]['id']})
        row = {'user_id': uid, 'telegram_message_id': mid,
               'direction': 'incoming', 'kind': kind, 'body': body,
               'ad_id': data.get('ad_id') if type(data.get('ad_id')) is int else None,
               'file_id': fid if kind != 'text' else None,
               'file_name': str(data.get('file_name') or '')[:255] or None,
               'file_size': data.get('file_size') if type(data.get('file_size')) is int else None}
        saved = db_request('POST', 'iran_support_messages', payload=[row],
                           prefer='return=representation')
        return jsonify({'status': 'saved', 'id': saved[0]['id']}), 201
    except (requests.RequestException, RuntimeError, ValueError, KeyError):
        app.logger.exception('Support incoming save failed')
        return jsonify({'error': 'Database unavailable'}), 503


@app.route('/bot/support/outbox', methods=['GET'])
def bot_support_outbox():
    if not authorized():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        rows = db_request('GET', 'iran_support_outbox', {
            'select': 'id,user_id,body,status', 'status': 'eq.pending',
            'order': 'id.asc', 'limit': 20
        })
        return jsonify({'outbox': rows})
    except (requests.RequestException, RuntimeError, ValueError):
        app.logger.exception('Support outbox read failed')
        return jsonify({'error': 'Database unavailable'}), 503


@app.route('/bot/support/outbox/<int:reply_id>/ack', methods=['POST'])
def bot_support_outbox_ack(reply_id):
    if not authorized():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get('status') not in ('sent', 'failed'):
        return jsonify({'error': 'Invalid status'}), 400
    try:
        rows = db_request('PATCH', 'iran_support_outbox',
            {'id': 'eq.' + str(reply_id), 'status': 'eq.pending'},
            {'status': data['status'], 'error': str(data.get('error') or '')[:500],
             'finished_at': datetime.now(timezone.utc).isoformat()},
            'return=representation')
        if not rows:
            return jsonify({'error': 'Reply not pending or not found'}), 409
        return jsonify({'status': rows[0]['status']})
    except (requests.RequestException, RuntimeError, ValueError):
        app.logger.exception('Support outbox acknowledgement failed')
        return jsonify({'error': 'Database unavailable'}), 503

# ==========================================
# Admin support capabilities (authenticated)
# ==========================================

@app.route('/admin/support/capabilities', methods=['GET', 'OPTIONS'])
def admin_support_capabilities():
    if request.method == 'OPTIONS':
        return '', 204
    if not admin_authorized():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'support_text_incoming': True,
        'support_text_outgoing': True,
        'support_photo_metadata_incoming': True,
        'support_document_metadata_incoming': True,
        'media_preview': False,
        'media_outgoing': False,
        'version': 'support-stage-2'
    })


# ==========================================
# Start Server
# ==========================================

if __name__ == '__main__':
    port = int(
        os.environ.get(
            'PORT',
            10000
        )
    )

    app.run(
        host='0.0.0.0',
        port=port
    )
