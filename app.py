import os, subprocess, time, hmac, hashlib, json, secrets, pickle
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, send_file, abort, request, make_response, redirect

app = Flask(__name__)
FDFS_BASE = '/opt/fdfs/storage0'
INDEX_CACHE_DIR = '/opt/fdfs/.cache'  # 索引持久化目录

# ── 安全配置 ──────────────────────────────────────────
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme123')
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
TOKEN_EXPIRE_HOURS = 8
MAX_LOGIN_ATTEMPTS = 5
LOCK_DURATION = 300

login_attempts = {}

os.makedirs(INDEX_CACHE_DIR, exist_ok=True)

# ── JWT ───────────────────────────────────────────────
def b64encode(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64decode(s):
    import base64
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def make_token():
    header = b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
    exp = int(time.time()) + TOKEN_EXPIRE_HOURS * 3600
    payload = b64encode(json.dumps({'exp': exp, 'iat': int(time.time())}).encode())
    sig_input = f'{header}.{payload}'.encode()
    sig = b64encode(hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest())
    return f'{header}.{payload}.{sig}'

def verify_token(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        header, payload, sig = parts
        sig_input = f'{header}.{payload}'.encode()
        expected = b64encode(hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return False
        data = json.loads(b64decode(payload))
        return data['exp'] >= int(time.time())
    except:
        return False

def check_password(password):
    expected = hmac.new(SECRET_KEY.encode(), ADMIN_PASSWORD.encode(), hashlib.sha256).hexdigest()
    actual   = hmac.new(SECRET_KEY.encode(), password.encode(),       hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, actual)

def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def is_locked(ip):
    info = login_attempts.get(ip, {})
    lu = info.get('locked_until', 0)
    if lu and time.time() < lu:
        return True, int(lu - time.time())
    return False, 0

def record_fail(ip):
    info = login_attempts.get(ip, {'count': 0, 'locked_until': 0})
    info['count'] += 1
    if info['count'] >= MAX_LOGIN_ATTEMPTS:
        info['locked_until'] = time.time() + LOCK_DURATION
        info['count'] = 0
    login_attempts[ip] = info

def record_success(ip):
    login_attempts.pop(ip, None)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fdfs_token') or request.headers.get('Authorization','').replace('Bearer ','')
        if not token or not verify_token(token):
            if request.path.startswith('/api/'):
                return jsonify({'error':'unauthorized'}), 401
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# ── 索引持久化 ────────────────────────────────────────
def cache_file(base_path):
    key = hashlib.md5(base_path.encode()).hexdigest()
    return os.path.join(INDEX_CACHE_DIR, f'{key}.pkl')

def save_index(base_path, files):
    try:
        with open(cache_file(base_path), 'wb') as f:
            pickle.dump({'path': base_path, 'files': files, 'time': time.time()}, f)
    except Exception as e:
        print(f'保存索引失败: {e}')

def load_index(base_path):
    cf = cache_file(base_path)
    if not os.path.exists(cf):
        return None
    try:
        with open(cf, 'rb') as f:
            data = pickle.load(f)
        age_hours = (time.time() - data['time']) / 3600
        print(f'加载缓存索引: {base_path}，共 {len(data["files"])} 个文件，缓存于 {age_hours:.1f} 小时前')
        return data['files']
    except Exception as e:
        print(f'加载索引失败: {e}')
        return None

# ── 内存索引 ──────────────────────────────────────────
index = {}
index_status = {}  # 'idle' | 'scanning:N' | 'done' | 'error:msg'
scan_process = {}

def safe_path(path):
    p = os.path.realpath(str(path))
    base = os.path.realpath(FDFS_BASE)
    return p if p.startswith(base) else base

def start_scan(base_path):
    tmp = f'/tmp/fdfs_{hashlib.md5(base_path.encode()).hexdigest()}.txt'
    cmd = (
        f'find {base_path} -type f '
        r'\( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" '
        r'-o -iname "*.gif" -o -iname "*.webp" -o -iname "*.bmp" \) '
        f'-printf "%T@ %s %P\\n" > {tmp} 2>/dev/null'
    )
    proc = subprocess.Popen(cmd, shell=True)
    scan_process[base_path] = (proc, tmp)
    index_status[base_path] = 'scanning:0'

def check_scan(base_path):
    if base_path not in scan_process:
        return
    proc, tmp = scan_process[base_path]
    if proc.poll() is None:
        try:
            r = subprocess.run(f'wc -l < {tmp}', shell=True, capture_output=True, text=True)
            index_status[base_path] = f'scanning:{r.stdout.strip()}'
        except:
            pass
        return
    # 进程结束，加载结果
    try:
        files = []
        with open(tmp, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(' ', 2)
                if len(parts) < 3:
                    continue
                mtime, size, rel = parts
                try:
                    size = int(float(size))
                    files.append({
                        'name':       Path(rel).name,
                        'name_lower': Path(rel).name.lower(),
                        'path':       rel,
                        'size':       size,
                        'size_human': f'{size/1024:.1f}KB' if size < 1024*1024 else f'{size/1024/1024:.1f}MB',
                        'mtime':      datetime.fromtimestamp(float(mtime)).strftime('%Y-%m-%d %H:%M')
                    })
                except:
                    continue
        files.sort(key=lambda x: x['mtime'], reverse=True)
        index[base_path] = files
        index_status[base_path] = 'done'
        save_index(base_path, files)   # 持久化到磁盘
        try:
            os.remove(tmp)
        except:
            pass
        del scan_process[base_path]
    except Exception as e:
        index_status[base_path] = f'error:{e}'

def ensure_index(base_path):
    st = index_status.get(base_path, 'idle')
    if st == 'idle':
        # 先尝试从磁盘加载
        cached = load_index(base_path)
        if cached is not None:
            index[base_path] = cached
            index_status[base_path] = 'done'
        else:
            start_scan(base_path)
    elif st.startswith('scanning'):
        check_scan(base_path)

def get_stats():
    result = []
    base = Path(FDFS_BASE)
    if not base.exists():
        return result
    dirs = sorted([d for d in base.iterdir() if d.is_dir()])
    targets = dirs if dirs else [base]
    for d in targets:
        try:
            out = subprocess.run(['df','-h',str(d)], capture_output=True, text=True).stdout.strip().split('\n')
            p = out[1].split() if len(out) > 1 else []
            st = index_status.get(str(d), 'idle')
            cached = len(index.get(str(d), []))
            progress = 0
            if st.startswith('scanning:'):
                try: progress = int(st.split(':')[1])
                except: pass
            # 检查磁盘缓存时间
            cf = cache_file(str(d))
            cache_age = ''
            if os.path.exists(cf):
                age_h = (time.time() - os.path.getmtime(cf)) / 3600
                if age_h < 1:
                    cache_age = f'{int(age_h*60)}分钟前'
                elif age_h < 24:
                    cache_age = f'{age_h:.1f}小时前'
                else:
                    cache_age = f'{age_h/24:.1f}天前'
            result.append({
                'dir': d.name, 'path': str(d), 'exists': True,
                'total': p[1] if len(p)>1 else '?',
                'used':  p[2] if len(p)>2 else '?',
                'available': p[3] if len(p)>3 else '?',
                'use_percent': p[4] if len(p)>4 else '?',
                'cached': cached, 'progress': progress,
                'cache_age': cache_age,
                'status': 'scanning' if st.startswith('scanning') else st
            })
        except Exception as e:
            result.append({'dir': d.name, 'path': str(d), 'exists': True, 'error': str(e)})
    return result

# ── 认证路由 ──────────────────────────────────────────
@app.route('/login', methods=['GET'])
def login_page():
    return '''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FastDFS 登录</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(135deg,#1a73e8,#0d47a1);min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#fff;border-radius:16px;padding:40px;width:360px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.logo{text-align:center;font-size:48px;margin-bottom:16px}
h1{text-align:center;font-size:20px;color:#333;margin-bottom:8px}
.sub{text-align:center;font-size:13px;color:#888;margin-bottom:28px}
label{font-size:13px;color:#555;font-weight:500;display:block;margin-bottom:6px}
input{width:100%;padding:11px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;outline:none;transition:.2s;margin-bottom:16px}
input:focus{border-color:#1a73e8;box-shadow:0 0 0 3px rgba(26,115,232,.1)}
.btn{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.btn:hover{background:#0d47a1}
.err{background:#fce8e6;border:1px solid #ea4335;color:#c62828;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:16px;display:none}
.tip{text-align:center;font-size:11px;color:#bbb;margin-top:16px}
</style></head><body>
<div class="box">
  <div class="logo">🖼️</div>
  <h1>FastDFS 文件管理</h1>
  <div class="sub">请输入访问密码</div>
  <div class="err" id="err"></div>
  <label>密码</label>
  <input type="password" id="pwd" placeholder="请输入密码" onkeydown="if(event.key==='Enter')login()">
  <button class="btn" onclick="login()">登 录</button>
  <div class="tip">连续失败 5 次将锁定 5 分钟</div>
</div>
<script>
async function login(){
  const pwd=document.getElementById("pwd").value;
  const err=document.getElementById("err");
  if(!pwd){err.textContent="请输入密码";err.style.display="block";return;}
  try{
    const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pwd})});
    const d=await r.json();
    if(d.success){window.location.href="/";}
    else{err.textContent=d.error||"密码错误";err.style.display="block";document.getElementById("pwd").value="";}
  }catch(e){err.textContent="请求失败";err.style.display="block";}
}
</script></body></html>'''

@app.route('/api/login', methods=['POST'])
def do_login():
    ip = get_ip()
    locked, remain = is_locked(ip)
    if locked:
        return jsonify({'success': False, 'error': f'登录失败次数过多，请 {remain} 秒后重试'}), 429
    data = request.get_json() or {}
    if not check_password(data.get('password', '')):
        record_fail(ip)
        locked, remain = is_locked(ip)
        if locked:
            return jsonify({'success': False, 'error': f'已锁定 {remain} 秒'}), 429
        left = MAX_LOGIN_ATTEMPTS - login_attempts.get(ip, {}).get('count', 0)
        return jsonify({'success': False, 'error': f'密码错误，还剩 {left} 次机会'}), 401
    record_success(ip)
    token = make_token()
    resp = make_response(jsonify({'success': True}))
    resp.set_cookie('fdfs_token', token, max_age=TOKEN_EXPIRE_HOURS*3600, httponly=True, samesite='Strict', secure=False)
    return resp

@app.route('/api/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie('fdfs_token')
    return resp

# ── 业务路由 ──────────────────────────────────────────
@app.route('/api/status')
@require_auth
def status():
    for path, st in list(index_status.items()):
        if st.startswith('scanning'):
            check_scan(path)
    return jsonify({'status':'running', 'storage_dirs':get_stats(), 'base':FDFS_BASE, 'time':datetime.now().isoformat()})

@app.route('/api/scan')
@require_auth
def scan():
    path = safe_path(request.args.get('path', FDFS_BASE))
    if path in scan_process:
        try: scan_process[path][0].kill()
        except: pass
        del scan_process[path]
    index_status.pop(path, None)
    index.pop(path, None)
    # 删除磁盘缓存，强制重新扫描
    cf = cache_file(path)
    if os.path.exists(cf):
        os.remove(cf)
    start_scan(path)
    return jsonify({'message': '开始扫描', 'path': path})

@app.route('/api/files')
@app.route('/api/files/<int:dir_index>')
@require_auth
def files(dir_index=None):
    path = safe_path(request.args.get('path', FDFS_BASE))
    page = int(request.args.get('page', 0))
    page_size = 100
    ensure_index(path)
    st = index_status.get(path, 'scanning')
    if st.startswith('scanning'):
        check_scan(path)
        st = index_status.get(path, 'scanning')
    if st.startswith('scanning'):
        try: progress = int(st.split(':')[1])
        except: progress = 0
        return jsonify({'status':'scanning', 'message':f'扫描中，已发现 {progress} 个文件...', 'files':[], 'total':0, 'total_pages':0, 'has_more':False})
    if st.startswith('error'):
        return jsonify({'status':'error', 'message':st, 'files':[], 'total':0, 'total_pages':0, 'has_more':False})
    all_files = index.get(path, [])
    total = len(all_files)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = page * page_size
    result = [{k:v for k,v in f.items() if k != 'name_lower'} for f in all_files[start:start+page_size]]
    return jsonify({'status':'done', 'files':result, 'page':page, 'total':total, 'total_pages':total_pages, 'has_more':start+page_size < total})

@app.route('/api/search')
@require_auth
def search():
    path = safe_path(request.args.get('path', FDFS_BASE))
    keyword = request.args.get('q', '').strip().lower()
    page = int(request.args.get('page', 0))
    page_size = 100
    if not keyword:
        return jsonify({'status':'error', 'message':'请输入搜索关键词', 'files':[], 'total':0})
    ensure_index(path)
    st = index_status.get(path, 'idle')
    if st != 'done':
        return jsonify({'status': st.split(':')[0], 'message':'索引尚未建立，请先扫描目录', 'files':[], 'total':0})
    all_files = index.get(path, [])
    keywords = keyword.split()
    matched = [f for f in all_files if all(k in f['name_lower'] for k in keywords)]
    total = len(matched)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = page * page_size
    result = [{k:v for k,v in f.items() if k != 'name_lower'} for f in matched[start:start+page_size]]
    return jsonify({'status':'done', 'files':result, 'total':total, 'total_pages':total_pages, 'page':page, 'has_more':start+page_size < total, 'keyword':keyword})

@app.route('/file/<path:filepath>')
@require_auth
def serve_file(filepath):
    full_path = Path(f'{FDFS_BASE}/{filepath}')
    if not full_path.exists() or not full_path.is_file():
        abort(404)
    return send_file(full_path, as_attachment=False)

@app.route('/download/<path:filepath>')
@require_auth
def download_file(filepath):
    full_path = Path(f'{FDFS_BASE}/{filepath}')
    if not full_path.exists() or not full_path.is_file():
        abort(404)
    return send_file(full_path, as_attachment=True, download_name=full_path.name)

@app.route('/')
@require_auth
def index_page():
    return r'''<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FastDFS 文件查看</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f2f5}
.hd{background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff;padding:16px 24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.hd h1{font-size:18px;font-weight:600;flex-shrink:0}
.search-bar{flex:1;min-width:200px;display:flex;gap:6px;align-items:center;background:rgba(255,255,255,.15);border-radius:8px;padding:5px 10px}
.search-bar input{flex:1;background:none;border:none;outline:none;color:#fff;font-size:13px}
.search-bar input::placeholder{color:rgba(255,255,255,.6)}
.search-bar button{background:rgba(255,255,255,.2);border:none;color:#fff;padding:3px 10px;border-radius:5px;cursor:pointer;font-size:12px;white-space:nowrap}
.search-bar button:hover{background:rgba(255,255,255,.3)}
.hd-right{display:flex;align-items:center;gap:10px;flex-shrink:0}
.dot{width:8px;height:8px;border-radius:50%;background:#34a853;display:inline-block;margin-right:5px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.logout-btn{background:rgba(255,255,255,.15);border:none;color:#fff;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px}
.logout-btn:hover{background:rgba(255,255,255,.25)}
.ct{max-width:1200px;margin:20px auto;padding:0 16px}
.summary{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:10px;margin-bottom:16px}
.sm{background:#fff;border-radius:10px;padding:12px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.08);cursor:pointer;transition:.2s;border:2px solid transparent}
.sm:hover,.sm.active{border-color:#1a73e8;background:#e8f0fe}
.sm .nm{font-weight:700;color:#1a73e8;font-size:13px}
.sm .pct{font-size:17px;font-weight:700;margin:3px 0}
.sm .inf{font-size:10px;color:#888;line-height:1.7}
.sc{font-size:10px;margin-top:4px;padding:2px 6px;border-radius:8px;display:inline-block}
.sc.done{background:#e6f4ea;color:#34a853}
.sc.scanning{background:#fff3cd;color:#f57c00}
.sc.idle{background:#f0f0f0;color:#999}
.bar{height:4px;background:#e0e0e0;border-radius:2px;margin-top:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:2px}
.card{background:#fff;border-radius:10px;padding:18px;box-shadow:0 2px 6px rgba(0,0,0,.08);margin-bottom:16px}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px}
.card-hd h2{font-size:14px;font-weight:600;color:#1a73e8}
.btn{background:#1a73e8;color:#fff;border:none;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px;text-decoration:none;display:inline-block}
.btn:hover{background:#0d47a1}.btn:disabled{background:#ccc;cursor:default}
.btn-o{background:#f57c00}.btn-o:hover{background:#e65100}
.pager{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.pager span{font-size:12px;color:#666}
.pager input{width:50px;padding:3px 6px;border:1px solid #ddd;border-radius:5px;font-size:12px;text-align:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:10px}
.img-card{border:1px solid #e8eaed;border-radius:8px;overflow:hidden;transition:.2s}
.img-card:hover{box-shadow:0 4px 12px rgba(0,0,0,.15);transform:translateY(-2px)}
.img-wrap{width:100%;height:108px;background:#f8f9fa;display:flex;align-items:center;justify-content:center;overflow:hidden}
.img-wrap img{width:100%;height:100%;object-fit:cover;cursor:zoom-in}
.no-prev{font-size:28px}
.img-info{padding:7px}
.fn{font-size:11px;font-weight:600;color:#333;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.meta{font-size:10px;color:#888;margin-top:2px}
.actions{display:flex;gap:4px;margin-top:5px}
.actions a{flex:1;text-align:center;padding:3px;border-radius:4px;font-size:11px;text-decoration:none;color:#fff;background:#1a73e8}
.actions a.dl{background:#34a853}
.empty{text-align:center;padding:40px;color:#999;font-size:14px}
.scanning-box{text-align:center;padding:40px}
.spin{font-size:36px;animation:spin 1s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.scanning-box p{color:#666;margin-top:12px;font-size:14px}
.scanning-box .sub{color:#999;font-size:12px;margin-top:6px}
.search-tip{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:8px 14px;margin-bottom:12px;font-size:13px;display:flex;align-items:center;justify-content:space-between}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:100;align-items:center;justify-content:center;flex-direction:column;gap:10px}
.modal.show{display:flex}
.modal img{max-width:92vw;max-height:86vh;border-radius:6px}
.modal-close{color:#fff;font-size:13px;cursor:pointer;background:rgba(255,255,255,.15);padding:5px 16px;border-radius:20px}
</style></head>
<body>
<div class="hd">
  <h1>🖼️ FastDFS</h1>
  <div class="search-bar">
    <input type="text" id="search-input" placeholder="搜索文件名，多词空格分隔..." onkeydown="if(event.key==='Enter')doSearch()">
    <button onclick="doSearch()">🔍 搜索</button>
    <button onclick="clearSearch()" id="btn-clear" style="display:none">✕ 清除</button>
  </div>
  <div class="hd-right">
    <span style="font-size:12px;opacity:.9"><span class="dot"></span><span id="st">连接中</span></span>
    <button class="logout-btn" onclick="logout()">退出</button>
  </div>
</div>
<div class="ct">
  <div class="card">
    <div class="card-hd">
      <h2>💾 存储目录</h2>
      <button class="btn" onclick="loadAll()">🔄 刷新</button>
    </div>
    <div class="summary" id="summary">加载中...</div>
  </div>
  <div class="card">
    <div class="card-hd">
      <h2 id="file-title">请点击上方目录</h2>
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
        <button class="btn btn-o" id="btn-rescan" onclick="rescan()" style="display:none">🔄 重新扫描</button>
        <div class="pager" id="pager" style="display:none">
          <button class="btn" id="btn-prev" onclick="changePage(currentPage-1)">◀</button>
          <span>第 <input type="number" id="page-input" min="1" value="1" onchange="jumpPage(this.value)"> / <span id="total-pages">?</span> 页</span>
          <button class="btn" id="btn-next" onclick="changePage(currentPage+1)">▶</button>
          <span id="total-info" style="font-size:11px;color:#888"></span>
        </div>
      </div>
    </div>
    <div id="search-tip" style="display:none"></div>
    <div id="file-list"><div class="empty">👆 点击目录卡片浏览，首次需要扫描建立索引</div></div>
  </div>
</div>
<div class="modal" id="modal" onclick="closeModal()">
  <img id="modal-img" src="" onclick="event.stopPropagation()">
  <div class="modal-close" onclick="closeModal()">✕ 关闭 (ESC)</div>
</div>
<script>
let currentPage=0, currentPath="", currentDir="", currentDirName="", scanTimer=null, isSearch=false, currentKw="";

function pctColor(p){const n=parseInt(p);if(isNaN(n))return"#1a73e8";if(n>90)return"#ea4335";if(n>70)return"#fbbc04";return"#34a853";}

async function loadAll(){
  try{
    const d=await(await fetch("/api/status")).json();
    document.getElementById("st").textContent="运行正常";
    const dirs=d.storage_dirs;
    if(!dirs.length){loadFiles(d.base,"",0,"根目录");return;}
    document.getElementById("summary").innerHTML=dirs.map(s=>{
      const pct=parseInt(s.use_percent)||0, color=pctColor(s.use_percent);
      const age=s.cache_age?` (${s.cache_age})`:"";
      const scLabel=s.status==="done"?`✅ ${s.cached.toLocaleString()}张${age}`:
                    s.status==="scanning"?`⏳ ${s.progress.toLocaleString()}...`:"点击扫描";
      const scClass=s.status==="done"?"done":s.status==="scanning"?"scanning":"idle";
      return`<div class="sm" onclick="loadFiles('${s.path}','${s.dir}',0,'${s.dir}')" id="sm-${s.dir}">
        <div class="nm">${s.dir}</div>
        <div class="pct" style="color:${color}">${s.use_percent||"?"}</div>
        <div class="inf">总${s.total||"?"}/余${s.available||"?"}</div>
        <div class="bar"><div class="bar-fill" style="width:${Math.min(pct,100)}%;background:${color}"></div></div>
        <div class="sc ${scClass}">${scLabel}</div>
      </div>`;
    }).join("");
  }catch(e){
    if(e.status===401||String(e).includes("401")){window.location.href="/login";return;}
    document.getElementById("st").textContent="连接失败";
  }
}

// path: 完整路径, dirName: 子目录名(用于路径拼接), page, label: 显示名
async function loadFiles(path, dirName, page, label){
  isSearch=false; currentPath=path; currentDirName=dirName; currentPage=page; currentDir=label;
  document.getElementById("search-tip").style.display="none";
  if(scanTimer){clearInterval(scanTimer);scanTimer=null;}
  document.querySelectorAll(".sm").forEach(el=>el.classList.remove("active"));
  const sm=document.getElementById(`sm-${label}`);if(sm)sm.classList.add("active");
  document.getElementById("file-title").textContent=label;
  document.getElementById("pager").style.display="none";
  document.getElementById("btn-rescan").style.display="";
  document.getElementById("file-list").innerHTML="<div class='empty'>⏳ 请求中...</div>";
  try{
    const resp=await fetch(`/api/files?path=${encodeURIComponent(path)}&page=${page}`);
    if(resp.status===401){window.location.href="/login";return;}
    const d=await resp.json();
    if(d.status==="scanning"){
      document.getElementById("file-list").innerHTML=`<div class="scanning-box"><div class="spin">⏳</div><p>后台扫描建立索引中</p><div class="sub">${d.message}<br>每5秒自动刷新</div></div>`;
      scanTimer=setInterval(()=>loadFiles(currentPath,currentDirName,currentPage,currentDir),5000);
      loadAll(); return;
    }
    if(d.status==="error"){document.getElementById("file-list").innerHTML=`<div class="empty">❌ ${d.message}</div>`;return;}
    if(scanTimer){clearInterval(scanTimer);scanTimer=null;}
    renderFiles(d, page, label, dirName);
    loadAll();
  }catch(e){document.getElementById("file-list").innerHTML=`<div class="empty">❌ 请求失败: ${e.message}</div>`;}
}

async function doSearch(){
  const kw=document.getElementById("search-input").value.trim();
  if(!kw){alert("请输入搜索关键词");return;}
  if(!currentPath){alert("请先选择一个目录");return;}
  isSearch=true; currentKw=kw; currentPage=0;
  document.getElementById("btn-clear").style.display="";
  document.getElementById("file-list").innerHTML="<div class='empty'>🔍 搜索中...</div>";
  await fetchSearch(0);
}

async function fetchSearch(page){
  try{
    const resp=await fetch(`/api/search?path=${encodeURIComponent(currentPath)}&q=${encodeURIComponent(currentKw)}&page=${page}`);
    if(resp.status===401){window.location.href="/login";return;}
    const d=await resp.json();
    if(d.status!=="done"){
      document.getElementById("file-list").innerHTML=`<div class="empty">⚠️ ${d.message}</div>`;
      return;
    }
    document.getElementById("search-tip").innerHTML=
      `<div class="search-tip">🔍 搜索 "<b>${currentKw}</b>" 共 <b>${d.total}</b> 个结果
       <button class="btn" onclick="clearSearch()" style="padding:2px 10px;font-size:11px">清除</button></div>`;
    document.getElementById("search-tip").style.display="block";
    currentPage=page;
    renderFiles(d, page, currentDir+" [搜索]", currentDirName);
  }catch(e){document.getElementById("file-list").innerHTML=`<div class="empty">❌ 搜索失败: ${e.message}</div>`;}
}

function clearSearch(){
  isSearch=false; currentKw="";
  document.getElementById("search-input").value="";
  document.getElementById("btn-clear").style.display="none";
  document.getElementById("search-tip").style.display="none";
  if(currentPath) loadFiles(currentPath, currentDirName, 0, currentDir);
}

function renderFiles(d, page, label, dirName){
  document.getElementById("total-pages").textContent=d.total_pages;
  document.getElementById("total-info").textContent=`共 ${d.total.toLocaleString()} 张`;
  document.getElementById("page-input").value=page+1;
  document.getElementById("page-input").max=d.total_pages;
  document.getElementById("btn-prev").disabled=page<=0;
  document.getElementById("btn-next").disabled=!d.has_more;
  document.getElementById("pager").style.display="flex";
  document.getElementById("file-title").textContent=`${label}（第${page+1}/${d.total_pages}页，共${d.total.toLocaleString()}张）`;
  if(!d.files.length){document.getElementById("file-list").innerHTML="<div class='empty'>📭 没有找到图片</div>";return;}
  // dirName 非空时拼接到路径前面
  const prefix = dirName ? dirName+"/" : "";
  document.getElementById("file-list").innerHTML=`<div class="grid">${d.files.map(f=>{
    const fp = prefix + f.path;
    return`<div class="img-card">
      <div class="img-wrap"><img src="/file/${fp}" loading="lazy" onclick="openModal('/file/${fp}')" onerror="this.parentElement.innerHTML='<div class=no-prev>📄</div>'"></div>
      <div class="img-info">
        <div class="fn" title="${f.name}">${f.name}</div>
        <div class="meta">${f.size_human} · ${f.mtime}</div>
        <div class="actions">
          <a href="/file/${fp}" target="_blank">查看</a>
          <a href="/download/${fp}" class="dl">下载</a>
        </div>
      </div>
    </div>`;
  }).join("")}</div>`;
}

async function rescan(){
  if(!currentPath)return;
  await fetch(`/api/scan?path=${encodeURIComponent(currentPath)}`);
  loadFiles(currentPath, currentDirName, 0, currentDir);
}

function changePage(p){
  if(p<0)return;
  if(isSearch) fetchSearch(p);
  else loadFiles(currentPath, currentDirName, p, currentDir);
  window.scrollTo({top:0,behavior:"smooth"});
}
function jumpPage(v){const p=parseInt(v)-1;if(!isNaN(p)&&p>=0)changePage(p);}

async function logout(){
  await fetch("/api/logout",{method:"POST"});
  window.location.href="/login";
}

function openModal(src){document.getElementById("modal-img").src=src;document.getElementById("modal").classList.add("show");}
function closeModal(){document.getElementById("modal").classList.remove("show");document.getElementById("modal-img").src="";}
document.addEventListener("keydown",e=>{
  if(e.key==="Escape")closeModal();
  if(e.key==="ArrowRight"&&currentPath&&document.activeElement.tagName!=="INPUT")changePage(currentPage+1);
  if(e.key==="ArrowLeft"&&currentPath&&document.activeElement.tagName!=="INPUT")changePage(currentPage-1);
});
loadAll();
setInterval(loadAll,15000);
</script></body></html>'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=False, threaded=True)
