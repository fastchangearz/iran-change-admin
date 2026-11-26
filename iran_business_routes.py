import requests
from flask import request, jsonify


def install_business_routes(app, db, authorized):

    @app.route('/bot/business/incoming', methods=['POST'])
    def business_incoming():

        if not authorized():
            return jsonify(error='Unauthorized'), 401

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify(error='Invalid JSON'), 400

        connection_id = data.get('business_connection_id')
        chat_id = data.get('telegram_chat_id')
        message_id = data.get('telegram_message_id')
        sender_id = data.get('sender_id')
        text = data.get('message_text')

        if (
            not isinstance(connection_id, str)
            or not connection_id.strip()
            or len(connection_id) > 512
            or type(chat_id) is not int
            or chat_id <= 0
            or type(sender_id) is not int
            or sender_id != chat_id
            or type(message_id) is not int
            or message_id <= 0
            or not isinstance(text, str)
            or not text.strip()
            or len(text) > 4096
        ):
            return jsonify(error='Invalid message'), 400

        identity = {
            'business_connection_id': f'eq.{connection_id}',
            'telegram_chat_id': f'eq.{chat_id}',
            'telegram_message_id': f'eq.{message_id}'
        }

        def save_pending(reason, candidates):

            row = {
                'business_connection_id': connection_id,
                'telegram_chat_id': chat_id,
                'telegram_message_id': message_id,
                'sender_id': sender_id,
                'message_text': text,
                'routing_status': 'pending',
                'routing_reason': reason,
                'candidate_threads': candidates
            }

            try:
                saved = db(
                    'POST',
                    'iran_business_inbox',
                    payload=[row],
                    prefer='return=representation'
                )

            except requests.HTTPError as exc:

                if (
                    exc.response is not None
                    and exc.response.status_code == 409
                ):
                    existing = db(
                        'GET',
                        'iran_business_inbox',
                        {
                            **identity,
                            'select': 'inbox_id,routing_status',
                            'limit': 1
                        }
                    )

                    if existing:
                        return jsonify(
                            status='already_queued',
                            inbox_id=existing[0]['inbox_id']
                        ), 200

                raise

            return jsonify(
                status='queued',
                reason=reason,
                inbox_id=saved[0]['inbox_id']
            ), 200

        try:

            existing = db(
                'GET',
                'iran_chat_messages',
                {
                    **identity,
                    'select': 'message_id,thread_id',
                    'limit': 1
                }
            )

            if existing:
                return jsonify(
                    status='already_saved',
                    message_id=existing[0]['message_id']
                ), 200

            queued = db(
                'GET',
                'iran_business_inbox',
                {
                    **identity,
                    'select': 'inbox_id,routing_status',
                    'limit': 1
                }
            )

            if queued:
                return jsonify(
                    status='already_queued',
                    inbox_id=queued[0]['inbox_id']
                ), 200

            threads = db(
                'GET',
                'iran_chat_threads',
                {
                    'select': (
                        'thread_id,agreement_id,'
                        'participant_id,participant_role,'
                        'business_connection_id,telegram_chat_id'
                    ),
                    'participant_id': f'eq.{sender_id}'
                }
            )

            active_threads = []
            candidates = []

            for thread in threads:

                agreements = db(
                    'GET',
                    'iran_chat_agreements',
                    {
                        'select': (
                            'agreement_id,ad_id,offer_id,status'
                        ),
                        'agreement_id': (
                            f"eq.{thread['agreement_id']}"
                        ),
                        'status': 'eq.active',
                        'limit': 1
                    }
                )

                if agreements:

                    agreement = agreements[0]

                    active_threads.append(thread)

                    candidates.append({
                        'thread_id': thread['thread_id'],
                        'agreement_id': agreement['agreement_id'],
                        'ad_id': agreement['ad_id'],
                        'offer_id': agreement['offer_id'],
                        'participant_role': thread['participant_role']
                    })

            if not active_threads:
                return save_pending(
                    'no_active_agreement',
                    candidates
                )

            if len(active_threads) != 1:
                return save_pending(
                    'multiple_active_agreements',
                    candidates
                )

            thread = active_threads[0]
            thread_id = thread['thread_id']
            role = thread['participant_role']

            if role not in ('owner', 'proposer'):
                return save_pending(
                    'invalid_role',
                    candidates
                )

            if thread.get('business_connection_id') not in (
                None, connection_id
            ):
                return save_pending(
                    'connection_mismatch',
                    candidates
                )

            if thread.get('telegram_chat_id') not in (
                None, chat_id
            ):
                return save_pending(
                    'chat_mismatch',
                    candidates
                )

            db(
                'PATCH',
                'iran_chat_threads',
                {
                    'thread_id': f'eq.{thread_id}'
                },
                {
                    'business_connection_id': connection_id,
                    'telegram_chat_id': chat_id
                },
                'return=minimal'
            )

            row = {
                'thread_id': thread_id,
                'sender_role': 'participant',
                'message_type': 'text',
                'message_text': text,
                'business_connection_id': connection_id,
                'telegram_chat_id': chat_id,
                'telegram_message_id': message_id,
                'delivery_status': 'received'
            }

            try:
                saved = db(
                    'POST',
                    'iran_chat_messages',
                    payload=[row],
                    prefer='return=representation'
                )

            except requests.HTTPError as exc:

                if (
                    exc.response is not None
                    and exc.response.status_code == 409
                ):
                    duplicate = db(
                        'GET',
                        'iran_chat_messages',
                        {
                            **identity,
                            'select': 'message_id',
                            'limit': 1
                        }
                    )

                    if duplicate:
                        return jsonify(
                            status='already_saved',
                            message_id=duplicate[0]['message_id']
                        ), 200

                raise

            return jsonify(
                status='saved',
                thread_id=thread_id,
                message_id=saved[0]['message_id']
            ), 201

        except (
            requests.RequestException,
            RuntimeError,
            ValueError,
            TypeError,
            KeyError,
            IndexError
        ):
            app.logger.exception(
                'Business incoming message failed'
            )

            return jsonify(
                error='Database operation failed'
            ), 503
