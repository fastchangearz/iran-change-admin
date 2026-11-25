from pathlib import Path
from flask import request, jsonify, send_file
from iran_staff_routes import authenticated_manager
import requests

def install_center(app, db):
    @app.get('/center')
    def center_page():
        r=send_file(Path(__file__).with_name('iran_center.html'))
        r.headers['Cache-Control']='no-store'
        return r

    @app.get('/center/api/cases')
    def cases():
        account, token=authenticated_manager()
        if not account or not token: return jsonify(error='Unauthorized'),401
        try:
            before=request.args.get('before',type=int)
            q={'select':'agreement_id,ad_id,offer_id,status,created_at','order':'agreement_id.desc','limit':100}
            if before: q['agreement_id']=f'lt.{before}'
            rows=db('GET','iran_chat_agreements',q)
            if rows:
                ids=','.join(str(int(r['ad_id'])) for r in rows)
                ads=db('GET','iran_ads',{'select':'ad_id,trade_type,amount,currency,method','ad_id':f'in.({ids})'})
                by={a['ad_id']:a for a in ads}
                for r in rows: r['ad']=by.get(r['ad_id'],{})
            return jsonify(cases=rows)
        except (requests.RequestException,RuntimeError,ValueError,KeyError,TypeError):
            app.logger.exception('Center cases failed');return jsonify(error='Database unavailable'),503

    @app.get('/center/api/messages/<int:thread_id>')
    def messages(thread_id):
        account,token=authenticated_manager()
        if not account or not token: return jsonify(error='Unauthorized'),401
        try:
            q={'select':'message_id,sender_role,message_type,message_text,created_at','thread_id':f'eq.{thread_id}','order':'message_id.desc','limit':100}
            before=request.args.get('before',type=int)
            if before:q['message_id']=f'lt.{before}'
            rows=db('GET','iran_chat_messages',q)
            return jsonify(messages=list(reversed(rows)))
        except (requests.RequestException,RuntimeError,ValueError,TypeError):
            app.logger.exception('Center messages failed');return jsonify(error='Database unavailable'),503
    @app.get('/center/api/threads/<int:agreement_id>')
    def center_threads(agreement_id):
        try:
            account, token = authenticated_manager()

            if not account or not token:
                return jsonify(error='Unauthorized'), 401

            if account.get('role') != 'manager':
                return jsonify(error='Forbidden'), 403

            agreements = db(
                'GET', 'iran_chat_agreements',
                {
                    'select': 'agreement_id,status',
                    'agreement_id': f'eq.{agreement_id}',
                    'limit': 1
                }
            )

            if not agreements:
                return jsonify(error='Agreement not found'), 404

            rows = db(
                'GET', 'iran_chat_threads',
                {
                    'select': 'thread_id,agreement_id,participant_role,created_at',
                    'agreement_id': f'eq.{agreement_id}',
                    'order': 'thread_id.asc'
                }
            )

            return jsonify(threads=rows)

        except (requests.RequestException, RuntimeError,
                ValueError, KeyError, TypeError):
            app.logger.exception('Center threads failed')
            return jsonify(error='Database unavailable'), 503
