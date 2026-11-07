import os
import hmac
from datetime import datetime, timezone
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
latest_stats = None
latest_ads, latest_offers, latest_conversations, latest_deals = [], [], [], []
TABLES = {'ads': ('iran_ads','ad_id'), 'offers': ('iran_offers','offer_id'), 'conversations': ('iran_conversations','conversation_id'), 'deals': ('iran_deals','ad_id,offer_id')}
FIELDS = {
 'ads': ('ad_id','trade_type','currency','amount','price','method','country','status','created_at'),
 'offers': ('offer_id','ad_id','proposed_price','status','created_at'),
 'conversations': ('conversation_id','ad_id','status','created_at','updated_at'),
 'deals': ('ad_id','offer_id','owner_confirmed','proposer_confirmed','cancel_requested','state','deadline','created_at')
}

def supabase_config():
    url = os.environ.get('SUPABASE_URL','').rstrip('/')
    key = os.environ.get('SUPABASE_SECRET_KEY','')
    if not url or not key: raise RuntimeError('Supabase is not configured')
    return url+'/rest/v1', {'apikey':key,'Authorization':'Bearer '+key,'Accept':'application/json','Content-Type':'application/json'}

def db_request(method, table, params=None, payload=None, prefer=None):
    base, headers = supabase_config()
    if prefer: headers['Prefer'] = prefer
    response = requests.request(method, base+'/'+table, headers=headers, params=params, json=payload, timeout=25)
    response.raise_for_status()
    if not response.content: return []
    return response.json()

def read_supabase(table):
    result, offset = [], 0
    while True:
        rows = db_request('GET', table, {'select':'*','limit':1000,'offset':offset})
        if not isinstance(rows,list): raise ValueError('Invalid database response')
        result.extend(rows)
        if len(rows)<1000: return result
        offset+=1000

def save_supabase(table, rows, conflict):
    for i in range(0,len(rows),100):
        db_request('POST',table,{'on_conflict':conflict},rows[i:i+100],'resolution=merge-duplicates,return=minimal')

def authorized():
    secret=os.environ.get('IRAN_CHANGE_SYNC_KEY','')
    supplied=request.headers.get('X-Sync-Key','')
    return bool(secret) and hmac.compare_digest(supplied,secret)

def admin_authorized():
    secret=os.environ.get('IRAN_CHANGE_ADMIN_KEY','')
    supplied=request.headers.get('X-Admin-Key','')
    return bool(secret) and hmac.compare_digest(supplied,secret)

def clean_rows(section,rows):
    if not isinstance(rows,list): raise ValueError('Invalid list')
    cleaned=[]
    for item in rows:
        if not isinstance(item,dict): raise ValueError('Invalid item')
        row={f:item[f] for f in FIELDS[section] if f in item}
        if section=='deals':
            for f in ('ad_id','offer_id'):
                if type(row.get(f)) is not int: raise ValueError('Invalid deal ID')
            for f in ('owner_confirmed','proposer_confirmed'):
                if type(row.get(f)) is not int or row[f] not in (0,1): raise ValueError('Invalid confirmation')
            if not isinstance(row.get('state'),str): raise ValueError('Invalid deal state')
            row['cancel_requested']=int(bool(item.get('cancel_requested',False)))
            row['deadline']=str(item.get('deadline') or '')
            row['created_at']=str(item.get('created_at') or '')
        if section=='conversations':
            for f in ('conversation_id','ad_id'):
                if type(row.get(f)) is not int: raise ValueError('Invalid conversation ID')
            if not isinstance(row.get('status'),str): raise ValueError('Invalid conversation status')
            row['created_at']=str(item.get('created_at') or '')
            row['updated_at']=str(item.get('updated_at') or '')
        cleaned.append(row)
    return cleaned

@app.after_request
def allow_dashboard(response):
    response.headers['Access-Control-Allow-Origin']='https://fastchangearz.github.io'
    response.headers['Access-Control-Allow-Headers']='Content-Type, X-Admin-Key'
    response.headers['Access-Control-Allow-Methods']='GET, POST, OPTIONS'
    return response

@app.route('/')
def home():
    return jsonify({'project':'Iran Change Admin API','status':'online','message':'Server is running'})

@app.route('/health')
def health():
    return jsonify({'status':'ok'})

@app.route('/status')
def status():
    if latest_stats is not None: return jsonify(latest_stats)
    try:
        ads=read_supabase('iran_ads')
        active=sum(1 for a in ads if str(a.get('status','')).lower() in ('active','published'))
        return jsonify({'total_ads':len(ads),'active_ads':active,'closed_ads':len(ads)-active})
    except (requests.RequestException,RuntimeError,ValueError):
        app.logger.exception('Statistics unavailable')
        return jsonify({'status':'waiting','message':'Database temporarily unavailable'}),503

@app.route('/sync-stats',methods=['POST'])
def sync_stats():
    global latest_stats
    if not authorized(): return jsonify({'error':'Unauthorized'}),401
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return jsonify({'error':'Invalid JSON'}),400
    keys=('total_ads','active_ads','closed_ads')
    if any(type(data.get(k)) is not int or data[k]<0 for k in keys): return jsonify({'error':'Invalid statistics'}),400
    if data['active_ads']+data['closed_ads']!=data['total_ads']: return jsonify({'error':'Inconsistent statistics'}),400
    latest_stats={k:data[k] for k in keys}
    return jsonify({'status':'saved'})

def get_section(section):
    try:
        rows=read_supabase(TABLES[section][0])
        if section=='deals':
            for row in rows: row['cancel_requested']=bool(row.get('cancel_requested'))
        return jsonify({section:rows,'count':len(rows)})
    except (requests.RequestException,RuntimeError,ValueError):
        app.logger.exception('Supabase read failed: %s',section)
        return jsonify({'error':'Database temporarily unavailable'}),503

def sync_section(section):
    global latest_ads,latest_offers,latest_conversations,latest_deals
    if not authorized(): return jsonify({'error':'Unauthorized'}),401
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or not isinstance(data.get(section),list): return jsonify({'error':'Invalid JSON'}),400
    try: rows=clean_rows(section,data[section])
    except (ValueError,TypeError): return jsonify({'error':'Invalid data'}),400
    table,conflict=TABLES[section]
    try: save_supabase(table,rows,conflict)
    except (requests.RequestException,RuntimeError):
        app.logger.exception('Supabase save failed: %s',section)
        return jsonify({'error':'Database save failed'}),503
    if section=='ads': latest_ads=rows
    elif section=='offers': latest_offers=rows
    elif section=='conversations': latest_conversations=rows
    elif section=='deals': latest_deals=rows
    return jsonify({'status':'saved','count':len(rows)})

@app.route('/ads')
def get_ads(): return get_section('ads')
@app.route('/sync-ads',methods=['POST'])
def sync_ads(): return sync_section('ads')
@app.route('/offers')
def get_offers(): return get_section('offers')
@app.route('/sync-offers',methods=['POST'])
def sync_offers(): return sync_section('offers')
@app.route('/conversations')
def get_conversations(): return get_section('conversations')
@app.route('/sync-conversations',methods=['POST'])
def sync_conversations(): return sync_section('conversations')
@app.route('/deals')
def get_deals(): return get_section('deals')
@app.route('/sync-deals',methods=['POST'])
def sync_deals(): return sync_section('deals')

@app.route('/admin/verify',methods=['POST','OPTIONS'])
def admin_verify():
    if request.method=='OPTIONS': return '',204
    if not admin_authorized(): return jsonify({'error':'Unauthorized'}),401
    return jsonify({'status':'authorized'})

@app.route('/admin/actions',methods=['GET','OPTIONS'])
def admin_actions():
    if request.method=='OPTIONS': return '',204
    if not admin_authorized(): return jsonify({'error':'Unauthorized'}),401
    try:
        rows=read_supabase('iran_admin_actions')
        rows.sort(key=lambda r:r.get('id',0),reverse=True)
        return jsonify({'actions':rows,'count':len(rows)})
    except (requests.RequestException,RuntimeError,ValueError):
        app.logger.exception('Admin actions unavailable')
        return jsonify({'error':'Database temporarily unavailable'}),503

@app.route('/admin/deal-action',methods=['POST','OPTIONS'])
def admin_deal_action():
    if request.method=='OPTIONS': return '',204
    if not admin_authorized(): return jsonify({'error':'Unauthorized'}),401
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return jsonify({'error':'Invalid JSON'}),400
    ad_id,offer_id=data.get('ad_id'),data.get('offer_id')
    action=data.get('action')
    reason=str(data.get('reason') or '').strip()
    if type(ad_id) is not int or type(offer_id) is not int or action not in ('review','cancel','complete'):
        return jsonify({'error':'Invalid action'}),400
    if ad_id<2512: return jsonify({'error':'Historical records are read-only'}),403
    if action=='cancel' and len(reason)<3: return jsonify({'error':'Cancellation reason required'}),400
    if len(reason)>1000: return jsonify({'error':'Reason too long'}),400
    try:
        matches=db_request('GET','iran_deals',{'select':'*','ad_id':'eq.'+str(ad_id),'offer_id':'eq.'+str(offer_id),'limit':1})
        if not matches: return jsonify({'error':'Deal not found'}),404
        deal=matches[0]
        old_state=str(deal.get('state') or '').lower()
        if old_state in ('completed','cancelled'): return jsonify({'error':'Deal is already final'}),409
        if action=='complete':
            if not (int(deal.get('owner_confirmed') or 0)==1 and int(deal.get('proposer_confirmed') or 0)==1):
                return jsonify({'error':'Both parties must confirm'}),409
            new_state='completed'
        elif action=='cancel': new_state='cancelled'
        else: new_state='admin_review'
        if old_state==new_state: return jsonify({'error':'Already in requested state'}),409
        now=datetime.now(timezone.utc).isoformat()
        audit={'ad_id':ad_id,'offer_id':offer_id,'action':action,'old_state':old_state,'new_state':new_state,'reason':reason,'created_at':now}
        db_request('POST','iran_admin_actions',payload=[audit],prefer='return=minimal')
        db_request('PATCH','iran_deals',{'ad_id':'eq.'+str(ad_id),'offer_id':'eq.'+str(offer_id)}, {'state':new_state},'return=minimal')
        if new_state in ('completed','cancelled'):
            ad_status='closed' if new_state=='completed' else 'active'
            db_request('PATCH','iran_ads',{'ad_id':'eq.'+str(ad_id)},{'status':ad_status},'return=minimal')
        return jsonify({'status':'saved','ad_id':ad_id,'offer_id':offer_id,'old_state':old_state,'new_state':new_state})
    except (requests.RequestException,RuntimeError,ValueError,TypeError):
        app.logger.exception('Admin deal action failed')
        return jsonify({'error':'Database operation failed'}),503

if __name__=='__main__':
    port=int(os.environ.get('PORT',10000))
    app.run(host='0.0.0.0',port=port)
