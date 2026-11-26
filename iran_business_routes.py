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

        try:
            identity = {
                'business_connection_id': f'eq.{connection_id}',
                'telegram_chat_id': f'eq.{chat_id}',
                'telegram_message_id': f'eq.{message_id}'
            }

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
                )

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

            for thread in threads:

                agreements = db(
                    'GET',
                    'iran_chat_agreements',
                    {
                        'select': 'agreement_id,status',
                        'agreement_id': (
                            f"eq.{thread['agreement_id']}"
                        ),
                        'status': 'eq.active',
                        'limit': 1
                    }
                )

                if agreements:
                    active_threads.append(thread)

            if not active_threads:
                return jsonify(
                    error='No active agreement'
                ), 404

            if len(active_threads) != 1:
                return jsonify(
                    error='Multiple active agreements',
                    status='manual_routing_required'
                ), 409

            thread = active_threads[0]
            thread_id = thread['thread_id']
            role = thread['participant_role']

            if role not in ('owner', 'proposer'):
                return jsonify(error='Invalid role'), 409

            if thread.get('business_connection_id') not in (
                None, connection_id
            ):
                return jsonify(
                    error='Connection mismatch'
                ), 409

            if thread.get('telegram_chat_id') not in (
                None, chat_id
            ):
                return jsonify(
                    error='Chat mismatch'
                ), 409

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
                'sender_role': role,
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
                        )

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
