"""Telegram Mini App participant routes for Iran Change. Never expose Supabase keys."""
import os
import json
import hmac
import hashlib
import time
from pathlib import Path
from urllib.parse import parse_qsl
import requests
from flask import jsonify, request, send_file


def install_user_minichat_routes(app, db_request):
    def telegram_user():
        # Diagnostics report only a reason code, never tokens, user IDs or initData.
        def reject(reason):
            app.logger.warning('MINICHAT_AUTH_REJECT reason=%s', reason)
            return None

        raw = request.headers.get('X-Telegram-Init-Data', '')
        if not raw:
            return reject('missing_init_data')
        if len(raw) > 8192:
            return reject('init_data_too_large')
        try:
            pairs = dict(parse_qsl(raw, keep_blank_values=True))
            supplied_hash = pairs.pop('hash', '')
            pairs.pop('signature', None)
            token = os.environ.get('IRAN_CHANGE_BOT_TOKEN', '').strip()
            if not token:
                return reject('missing_render_bot_token')
            if len(supplied_hash) != 64:
                return reject('missing_or_invalid_hash')
            auth_date = int(pairs.get('auth_date', '0'))
            if auth_date > time.time() + 60:
                return reject('auth_date_in_future')
            if time.time() - auth_date > 86400:
                return reject('auth_date_expired')
            data_check = '\n'.join(f'{k}={v}' for k, v in sorted(pairs.items()))
            secret = hmac.new(b'WebAppData', token.encode(), hashlib.sha256).digest()
            expected = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, supplied_hash):
                return reject('hash_mismatch')
            uid = int(json.loads(pairs['user'])['id'])
            if uid <= 0:
                return reject('invalid_user_id')
            return uid
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return reject('invalid_init_data_format')

    def fail(exc):
        app.logger.exception('Participant minichat database error')
        return jsonify({'error': 'Database temporarily unavailable'}), 503

    def owned_thread(thread_id, uid):
        rows = db_request('GET', 'iran_chat_threads', {
            'select': 'thread_id,agreement_id,participant_role,participant_id',
            'thread_id': f'eq.{thread_id}', 'participant_id': f'eq.{uid}', 'limit': 1})
        if not rows:
            return None, None
        agreement = db_request('GET', 'iran_chat_agreements', {
            'select': 'agreement_id,ad_id,status',
            'agreement_id': f"eq.{rows[0]['agreement_id']}", 'limit': 1})
        return rows[0], agreement[0] if agreement else None

    @app.route('/minichat', methods=['GET'])
    def minichat_user_page():
        return send_file(Path(__file__).resolve().parent / 'iran_minichat_user.html', mimetype='text/html')

    @app.route('/minichat/api/threads', methods=['GET'])
    def user_threads():
        uid = telegram_user()
        if uid is None:
            return jsonify({'error': 'Open this page from the Telegram bot'}), 401
        try:
            threads = db_request('GET', 'iran_chat_threads', {
                'select': 'thread_id,agreement_id,participant_role',
                'participant_id': f'eq.{uid}', 'order': 'thread_id.desc', 'limit': 100})
            result = []
            for thread in threads:
                agreements = db_request('GET', 'iran_chat_agreements', {
                    'select': 'ad_id,status',
                    'agreement_id': f"eq.{thread['agreement_id']}", 'limit': 1})
                if agreements:
                    result.append({**thread, 'ad_id': agreements[0]['ad_id'], 'status': agreements[0]['status']})
            return jsonify({'threads': result})
        except (requests.RequestException, RuntimeError, ValueError, TypeError, KeyError) as exc:
            return fail(exc)

    @app.route('/minichat/api/messages/<int:thread_id>', methods=['GET'])
    def user_messages(thread_id):
        uid = telegram_user()
        if uid is None:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            thread, agreement = owned_thread(thread_id, uid)
            if not thread or not agreement:
                return jsonify({'error': 'Thread not found'}), 404
            messages = db_request('GET', 'iran_chat_messages', {
                'select': 'message_id,sender_role,message_type,message_text,created_at',
                'thread_id': f'eq.{thread_id}', 'order': 'message_id.desc', 'limit': 200})
            messages.reverse()
            return jsonify({'messages': messages, 'status': agreement['status']})
        except (requests.RequestException, RuntimeError, ValueError, TypeError, KeyError) as exc:
            return fail(exc)

    @app.route('/minichat/api/send', methods=['POST'])
    def user_send():
        uid = telegram_user()
        if uid is None:
            return jsonify({'error': 'Unauthorized'}), 401
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid JSON'}), 400
        try:
            thread_id = int(data.get('thread_id'))
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid thread'}), 400
        msg = data.get('message_text')
        if thread_id <= 0 or not isinstance(msg, str) or not msg.strip() or len(msg) > 4000:
            return jsonify({'error': 'Invalid message'}), 400
        try:
            thread, agreement = owned_thread(thread_id, uid)
            if not thread or not agreement:
                return jsonify({'error': 'Thread not found'}), 404
            if agreement['status'] != 'active':
                return jsonify({'error': 'Agreement is closed'}), 409
            saved = db_request('POST', 'iran_chat_messages', payload=[{
                'thread_id': thread_id, 'sender_role': 'participant',
                'message_type': 'text', 'message_text': msg.strip()
            }], prefer='return=representation')
            return jsonify({'message': saved[0]}), 201
        except (requests.RequestException, RuntimeError, ValueError, TypeError, KeyError, IndexError) as exc:
            return fail(exc)
