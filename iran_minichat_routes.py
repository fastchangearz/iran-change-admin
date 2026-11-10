"""Iran Change mini-chat server: phase 1 (admin + bot authenticated API).
Participant Telegram Mini App endpoints are deliberately NOT enabled yet.
"""
import requests
from flask import jsonify, request


def install_minichat_routes(app, db_request, admin_authorized, authorized):
    def failure(exc, operation):
        app.logger.exception('Mini-chat %s failed', operation)
        return jsonify({'error': 'Database operation failed'}), 503

    @app.route('/admin/minichat/agreements', methods=['GET', 'OPTIONS'])
    def minichat_agreements():
        if request.method == 'OPTIONS':
            return '', 204
        if not admin_authorized():
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            rows = db_request('GET', 'iran_chat_agreements',
                              {'select': 'agreement_id,ad_id,offer_id,status,created_at,closed_at',
                               'order': 'agreement_id.desc', 'limit': 200})
            return jsonify({'agreements': rows, 'count': len(rows)})
        except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
            return failure(exc, 'agreements')

    @app.route('/admin/minichat/threads/<int:agreement_id>', methods=['GET', 'OPTIONS'])
    def minichat_threads(agreement_id):
        if request.method == 'OPTIONS':
            return '', 204
        if not admin_authorized():
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            agreements = db_request('GET', 'iran_chat_agreements',
                                    {'select': 'agreement_id,status', 'agreement_id': f'eq.{agreement_id}', 'limit': 1})
            if not agreements:
                return jsonify({'error': 'Agreement not found'}), 404
            rows = db_request('GET', 'iran_chat_threads',
                              {'select': 'thread_id,agreement_id,participant_role,created_at',
                               'agreement_id': f'eq.{agreement_id}', 'order': 'thread_id.asc'})
            return jsonify({'threads': rows})
        except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
            return failure(exc, 'threads')

    @app.route('/admin/minichat/messages/<int:thread_id>', methods=['GET', 'OPTIONS'])
    def minichat_messages(thread_id):
        if request.method == 'OPTIONS':
            return '', 204
        if not admin_authorized():
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            threads = db_request('GET', 'iran_chat_threads',
                                 {'select': 'thread_id', 'thread_id': f'eq.{thread_id}', 'limit': 1})
            if not threads:
                return jsonify({'error': 'Thread not found'}), 404
            rows = db_request('GET', 'iran_chat_messages',
                              {'select': 'message_id,thread_id,sender_role,message_type,message_text,file_reference,created_at',
                               'thread_id': f'eq.{thread_id}', 'order': 'message_id.asc', 'limit': 200})
            return jsonify({'messages': rows})
        except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
            return failure(exc, 'messages')

    @app.route('/admin/minichat/send', methods=['POST', 'OPTIONS'])
    def minichat_send():
        if request.method == 'OPTIONS':
            return '', 204
        if not admin_authorized():
            return jsonify({'error': 'Unauthorized'}), 401
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({'error': 'Invalid JSON'}), 400
        try:
            thread_id = int(body.get('thread_id'))
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid thread_id'}), 400
        message = body.get('message_text')
        if thread_id <= 0 or not isinstance(message, str) or not message.strip() or len(message) > 4000:
            return jsonify({'error': 'Invalid message'}), 400
        try:
            threads = db_request('GET', 'iran_chat_threads',
                                 {'select': 'thread_id,agreement_id', 'thread_id': f'eq.{thread_id}', 'limit': 1})
            if not threads:
                return jsonify({'error': 'Thread not found'}), 404
            agreements = db_request('GET', 'iran_chat_agreements',
                                    {'select': 'status', 'agreement_id': f"eq.{threads[0]['agreement_id']}", 'limit': 1})
            if not agreements or agreements[0]['status'] != 'active':
                return jsonify({'error': 'Agreement is not active'}), 409
            rows = db_request('POST', 'iran_chat_messages', payload=[{
                'thread_id': thread_id, 'sender_role': 'admin',
                'message_type': 'text', 'message_text': message.strip()
            }], prefer='return=representation')
            return jsonify({'message': rows[0]}), 201
        except (requests.RequestException, RuntimeError, ValueError, TypeError, KeyError, IndexError) as exc:
            return failure(exc, 'send')

    @app.route('/bot/minichat/agreement', methods=['POST'])
    def minichat_create_agreement():
        if not authorized():
            return jsonify({'error': 'Unauthorized'}), 401
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({'error': 'Invalid JSON'}), 400
        try:
            ad_id, offer_id, owner_id, proposer_id = (
                int(body[k]) for k in ('ad_id', 'offer_id', 'owner_id', 'proposer_id')
            )
        except (KeyError, ValueError, TypeError):
            return jsonify({'error': 'Invalid identifiers'}), 400
        if min(ad_id, offer_id, owner_id, proposer_id) <= 0 or owner_id == proposer_id:
            return jsonify({'error': 'Invalid participants'}), 400
        try:
            # Verify the existing synchronized deal is confirmed by both sides.
            deals = db_request('GET', 'iran_deals',
                               {'select': 'ad_id,offer_id,owner_confirmed,proposer_confirmed,state',
                                'ad_id': f'eq.{ad_id}', 'offer_id': f'eq.{offer_id}', 'limit': 1})
            if not deals or int(deals[0]['owner_confirmed'] or 0) != 1 or int(deals[0]['proposer_confirmed'] or 0) != 1:
                return jsonify({'error': 'Deal not fully confirmed'}), 409
            if str(deals[0].get('state') or '').lower() in ('cancelled', 'canceled', 'completed'):
                return jsonify({'error': 'Deal is closed'}), 409
            matches = db_request('GET', 'iran_chat_agreements',
                                 {'select': 'agreement_id,owner_id,proposer_id,status',
                                  'ad_id': f'eq.{ad_id}', 'offer_id': f'eq.{offer_id}',
                                  'order': 'agreement_id.desc', 'limit': 1})
            if matches:
                record = matches[0]
                if int(record['owner_id']) != owner_id or int(record['proposer_id']) != proposer_id:
                    return jsonify({'error': 'Participant mismatch'}), 409
                agreement_id = int(record['agreement_id'])
            else:
                created = db_request('POST', 'iran_chat_agreements', payload=[{
                    'ad_id': ad_id, 'offer_id': offer_id,
                    'owner_id': owner_id, 'proposer_id': proposer_id,
                    'status': 'active'
                }], prefer='return=representation')
                agreement_id = int(created[0]['agreement_id'])
            threads = db_request('GET', 'iran_chat_threads',
                                 {'select': 'thread_id,participant_role,participant_id',
                                  'agreement_id': f'eq.{agreement_id}'})
            for role, uid in (('owner', owner_id), ('proposer', proposer_id)):
                existing = next((r for r in threads if r['participant_role'] == role), None)
                if existing and int(existing['participant_id']) != uid:
                    return jsonify({'error': 'Thread participant mismatch'}), 409
                if not existing:
                    db_request('POST', 'iran_chat_threads', payload=[{
                        'agreement_id': agreement_id, 'participant_role': role,
                        'participant_id': uid
                    }], prefer='return=minimal')
            return jsonify({'agreement_id': agreement_id, 'status': 'ready'}), 200
        except (requests.RequestException, RuntimeError, ValueError, TypeError, KeyError, IndexError) as exc:
            return failure(exc, 'create agreement')
