from pathlib import Path
from flask import request, jsonify, send_file
from iran_staff_routes import authenticated_manager
import requests
import os, uuid, io
from PIL import Image
from urllib.parse import quote


def install_center(app, db):

    @app.route('/center/api/templates', methods=['GET', 'POST'])
    def center_templates():
        from uuid import UUID
        account, token = authenticated_manager()
        if not account or not token:
            return jsonify(error='Unauthorized'), 401
        if account.get('role') != 'manager':
            return jsonify(error='Forbidden'), 403
        table = 'iran_center_templates'
        try:
            if request.method == 'GET':
                return jsonify(templates=db('GET', table, {'select':'*','order':'position.asc,created_at.asc'}))
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify(error='Invalid data'), 400
            action = data.get('action')
            if action not in ('create','update','delete'):
                return jsonify(error='Invalid action'), 400
            filters = None
            if action != 'create':
                try:
                    filters = {'id':'eq.' + str(UUID(str(data.get('id'))))}
                except ValueError:
                    return jsonify(error='Invalid ID'), 400
            if action == 'delete':
                rows = db('DELETE', table, filters, prefer='return=representation')
            else:
                category, title, body = (data.get(k) for k in ('category','title','body'))
                if category not in ('خریدار','فروشنده','مشترک') or not isinstance(title,str) or not isinstance(body,str) or not 1 <= len(title.strip()) <= 120 or not 1 <= len(body.strip()) <= 4000:
                    return jsonify(error='Invalid template'), 400
                payload = dict(category=category,title=title.strip(),body=body.strip())
                if 'position' in data:
                    if type(data['position']) is not int or not -100000 <= data['position'] <= 100000:
                        return jsonify(error='Invalid position'), 400
                    payload['position'] = data['position']
                rows = db('POST' if action == 'create' else 'PATCH', table, filters, payload, 'return=representation')
            if not rows:
                return jsonify(error='Template not found'), 404
            return jsonify(ok=True)
        except Exception:
            app.logger.exception('Center templates failed')
            return jsonify(error='Database operation failed'), 503


    @app.get('/center-pwa/<name>')
    def center_pwa_asset(name):
        types = {'center.webmanifest': 'application/manifest+json',
                 'center-sw.js': 'application/javascript',
                 'center-icon-192.png': 'image/png',
                 'center-icon-512.png': 'image/png'}
        if name not in types:
            return '', 404
        response = send_file(Path(__file__).with_name(name), mimetype=types[name])
        response.headers['Cache-Control'] = 'no-cache'
        if name == 'center-sw.js':
            response.headers['Service-Worker-Allowed'] = '/'
        return response


    @app.get('/center')
    def center_page():
        r = send_file(
            Path(__file__).with_name('iran_center.html')
        )
        r.headers['Cache-Control'] = 'no-store'
        return r

    @app.get('/center/api/cases')
    def cases():

        account, token = authenticated_manager()

        if not account or not token:
            return jsonify(error='Unauthorized'), 401

        if account.get('role') != 'manager':
            return jsonify(error='Forbidden'), 403

        try:
            before = request.args.get('before', type=int)

            q = {
                'select': (
                    'agreement_id,ad_id,offer_id,'
                    'status,created_at'
                ),
                'order': 'agreement_id.desc',
                'limit': 100
            }

            if before:
                q['agreement_id'] = f'lt.{before}'

            rows = db(
                'GET',
                'iran_chat_agreements',
                q
            )

            if rows:

                ids = ','.join(
                    str(int(r['ad_id']))
                    for r in rows
                )

                ads = db(
                    'GET',
                    'iran_ads',
                    {
                        'select': (
                            'ad_id,trade_type,amount,'
                            'currency,method'
                        ),
                        'ad_id': f'in.({ids})'
                    }
                )

                by = {
                    a['ad_id']: a
                    for a in ads
                }

                for r in rows:
                    r['ad'] = by.get(r['ad_id'], {})

            response = jsonify(cases=rows)
            response.headers['Cache-Control'] = 'no-store'

            return response

        except (
            requests.RequestException,
            RuntimeError,
            ValueError,
            KeyError,
            TypeError
        ):
            app.logger.exception('Center cases failed')

            return jsonify(
                error='Database unavailable'
            ), 503

    @app.post('/center/api/photo')
    def center_photo():
        account, token = authenticated_manager()
        if not account or not token:
            return jsonify(error='Unauthorized'), 401
        if account.get('role') != 'manager':
            return jsonify(error='Forbidden'), 403
        if request.content_length and request.content_length > 11 * 1024 * 1024:
            return jsonify(error='File too large'), 413
        try:
            tid = int(request.form.get('thread_id', '0'))
            caption = request.form.get('caption', '').strip()
            f = request.files.get('file')
            if tid <= 0 or not f or len(caption) > 1024:
                return jsonify(error='Invalid photo or caption'), 400
            raw = f.stream.read(10 * 1024 * 1024 + 1)
            if len(raw) > 10 * 1024 * 1024:
                return jsonify(error='File too large'), 413
            try:
                with Image.open(io.BytesIO(raw)) as im:
                    if im.format not in ('JPEG', 'PNG') or im.width * im.height > 25000000 or im.width + im.height > 10000 or max(im.size) > 20 * min(im.size):
                        return jsonify(error='Unsupported image dimensions or format'), 400
                    im.verify()
                    ext = 'jpg' if im.format == 'JPEG' else 'png'
            except Exception:
                return jsonify(error='Invalid image'), 400
            ts = db('GET','iran_chat_threads',{'select':'*','thread_id':f'eq.{tid}','limit':1})
            if not ts: return jsonify(error='Thread not found'),404
            t = ts[0]
            aa = db('GET','iran_chat_agreements',{'select':'*','agreement_id':f"eq.{t['agreement_id']}",'limit':1})
            role = t['participant_role']
            if not aa or aa[0]['status'] != 'active' or role not in ('owner','proposer') or aa[0][role+'_id'] != t['participant_id'] or t['telegram_chat_id'] != t['participant_id'] or not t['business_connection_id']:
                return jsonify(error='No verified business recipient'),409
            path = f"business-photos/{tid}/{uuid.uuid4().hex}.{ext}"
            url = os.environ['SUPABASE_URL'].rstrip('/') + '/storage/v1/object/iran-change-documents/' + quote(path,safe='/')
            key = os.environ['SUPABASE_SERVICE_ROLE_KEY']
            headers = {'apikey':key,'Authorization':'Bearer '+key,'Content-Type':'image/jpeg' if ext=='jpg' else 'image/png','x-upsert':'false'}
            requests.post(url,headers=headers,data=raw,timeout=(10,30)).raise_for_status()
            rows = db('POST','iran_chat_messages',payload=[dict(thread_id=tid,sender_role='admin',message_type='file',message_text=caption or 'عکس',file_reference=path,business_connection_id=t['business_connection_id'],telegram_chat_id=t['telegram_chat_id'],delivery_status='pending_v2')],prefer='return=representation')
            return jsonify(message=rows[0]),201
        except Exception:
            app.logger.exception('Center photo failed')
            return jsonify(error='Photo not confirmed; check history before retry'),503

    @app.get('/center/api/messages/<int:thread_id>')
    def messages(thread_id):

        account, token = authenticated_manager()

        if not account or not token:
            return jsonify(error='Unauthorized'), 401

        if account.get('role') != 'manager':
            return jsonify(error='Forbidden'), 403

        try:

            q = {
                'select': (
                    'message_id,sender_role,message_type,'
                    'message_text,created_at,delivery_status,delivery_error,file_reference'
                ),
                'thread_id': f'eq.{thread_id}',
                'order': 'message_id.desc',
                'limit': 100
            }

            before = request.args.get(
                'before',
                type=int
            )

            if before:
                q['message_id'] = f'lt.{before}'

            rows = db(
                'GET',
                'iran_chat_messages',
                q
            )

            response = jsonify(
                messages=list(reversed(rows))
            )

            response.headers['Cache-Control'] = 'no-store'

            return response

        except (
            requests.RequestException,
            RuntimeError,
            ValueError,
            TypeError
        ):
            app.logger.exception(
                'Center messages failed'
            )

            return jsonify(
                error='Database unavailable'
            ), 503

    @app.get('/center/api/threads/<int:agreement_id>')
    def center_threads(agreement_id):

        try:

            account, token = authenticated_manager()

            if not account or not token:
                return jsonify(error='Unauthorized'), 401

            if account.get('role') != 'manager':
                return jsonify(error='Forbidden'), 403

            agreements = db(
                'GET',
                'iran_chat_agreements',
                {
                    'select': 'agreement_id,status',
                    'agreement_id': f'eq.{agreement_id}',
                    'limit': 1
                }
            )

            if not agreements:
                return jsonify(
                    error='Agreement not found'
                ), 404

            rows = db(
                'GET',
                'iran_chat_threads',
                {
                    'select': (
                        'thread_id,agreement_id,'
                        'participant_role,created_at'
                    ),
                    'agreement_id': f'eq.{agreement_id}',
                    'order': 'thread_id.asc'
                }
            )

            response = jsonify(threads=rows)
            response.headers['Cache-Control'] = 'no-store'

            return response

        except (
            requests.RequestException,
            RuntimeError,
            ValueError,
            KeyError,
            TypeError
        ):
            app.logger.exception(
                'Center threads failed'
            )

            return jsonify(
                error='Database unavailable'
            ), 503

    @app.get('/center/api/inbox')
    def center_inbox():

        try:

            account, token = authenticated_manager()

            if not account or not token:
                return jsonify(error='Unauthorized'), 401

            if account.get('role') != 'manager':
                return jsonify(error='Forbidden'), 403

            query = {
                'select': (
                    'inbox_id,sender_id,message_text,'
                    'routing_status,routing_reason,'
                    'candidate_threads,created_at'
                ),
                'routing_status': 'eq.pending',
                'order': 'inbox_id.desc',
                'limit': 100
            }

            before = request.args.get(
                'before',
                type=int
            )

            if before:
                query['inbox_id'] = f'lt.{before}'

            rows = db(
                'GET',
                'iran_business_inbox',
                query
            )

            candidates = [c for row in rows for c in (row.get('candidate_threads') or [])]
            ids = sorted({int(c['ad_id']) for c in candidates if c.get('ad_id')})
            if ids:
                ads = db('GET', 'iran_ads', {'select':'ad_id,trade_type',
                    'ad_id':'in.(' + ','.join(map(str, ids)) + ')'})
                types = {a['ad_id']: a.get('trade_type') for a in ads}
                for c in candidates:
                    c['trade_type'] = types.get(c.get('ad_id'))

            response = jsonify(messages=rows)
            response.headers['Cache-Control'] = 'no-store'

            return response

        except (
            requests.RequestException,
            RuntimeError,
            ValueError,
            KeyError,
            TypeError
        ):
            app.logger.exception(
                'Center inbox failed'
            )

            return jsonify(
                error='Database unavailable'
            ), 503

    @app.post('/center/api/inbox/assign')
    def center_inbox_assign():

        try:

            account, token = authenticated_manager()

            if not account or not token:
                return jsonify(error='Unauthorized'), 401

            if account.get('role') != 'manager':
                return jsonify(error='Forbidden'), 403

            data = request.get_json(silent=True)

            if not isinstance(data, dict):
                return jsonify(
                    error='اطلاعات نامعتبر است.'
                ), 400

            inbox_id = data.get('inbox_id')
            thread_id = data.get('thread_id')

            if (
                type(inbox_id) is not int
                or type(thread_id) is not int
                or not 1 <= inbox_id <= 9223372036854775807
                or not 1 <= thread_id <= 9223372036854775807
            ):
                return jsonify(
                    error='شناسه پیام یا گفتگو نامعتبر است.'
                ), 400

            result = db(
                'POST',
                'rpc/iran_assign_business_message',
                payload={
                    'p_inbox_id': inbox_id,
                    'p_thread_id': thread_id
                }
            )

            if type(result) is not int or result <= 0:
                raise ValueError(
                    'Invalid assignment response'
                )

            app.logger.info(
                'Inbox assignment completed: '
                'inbox=%s thread=%s message=%s',
                inbox_id,
                thread_id,
                result
            )

            response = jsonify(
                status='assigned',
                inbox_id=inbox_id,
                thread_id=thread_id,
                message_id=result,
                message='پیام با موفقیت به پرونده اختصاص یافت.'
            )

            response.headers['Cache-Control'] = 'no-store'

            return response, 200

        except requests.HTTPError as exc:

            response = exc.response
            detail = ''
            code = ''

            if response is not None:
                try:
                    body = response.json()

                    if isinstance(body, dict):
                        detail = body.get('message', '')
                        code = body.get('code', '')

                except ValueError:
                    pass

            errors = {
                'Inbox message not found': (
                    'پیام موردنظر پیدا نشد.',
                    404
                ),
                'Message already processed': (
                    'این پیام قبلاً بررسی شده است.',
                    409
                ),
                'Invalid sender': (
                    'فرستنده پیام نامعتبر است.',
                    409
                ),
                'Thread is not a candidate': (
                    'این گفتگو متعلق به پرونده‌های پیشنهادی نیست.',
                    409
                ),
                'Thread not found': (
                    'گفتگوی موردنظر پیدا نشد.',
                    404
                ),
                'Participant mismatch': (
                    'فرستنده متعلق به این گفتگو نیست.',
                    409
                ),
                'Agreement not found': (
                    'پرونده موردنظر پیدا نشد.',
                    404
                ),
                'Agreement is not active': (
                    'این پرونده دیگر فعال نیست.',
                    409
                ),
                'Owner mismatch': (
                    'صاحب آگهی مطابقت ندارد.',
                    409
                ),
                'Proposer mismatch': (
                    'پیشنهاددهنده مطابقت ندارد.',
                    409
                ),
                'Invalid participant role': (
                    'نقش طرف معامله نامعتبر است.',
                    409
                ),
                'Business connection mismatch': (
                    'اتصال تلگرام مطابقت ندارد.',
                    409
                ),
                'Telegram chat mismatch': (
                    'گفتگوی تلگرام مطابقت ندارد.',
                    409
                )
            }

            if isinstance(detail, str) and detail in errors:

                message, status = errors[detail]

                return jsonify(
                    error=message
                ), status

            if code == '23505':
                return jsonify(
                    error='این پیام قبلاً ثبت شده است.'
                ), 409

            app.logger.exception(
                'Inbox assignment database error'
            )

            return jsonify(
                error='خطا در اختصاص پیام؛ صندوق انتظار را به‌روزرسانی کنید.'
            ), 503

        except (
            requests.RequestException,
            RuntimeError,
            ValueError,
            KeyError,
            TypeError
        ):
            app.logger.exception(
                'Center inbox assignment failed'
            )

            return jsonify(
                error='نتیجه انتقال نامشخص است؛ صندوق انتظار را به‌روزرسانی کنید.'
            ), 503
