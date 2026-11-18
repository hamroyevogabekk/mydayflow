from flask import Flask, request, jsonify, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, re, time, json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'classroom.db')
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'DAYFLOW-CHANGE-THIS-SECRET-BEFORE-PRODUCTION')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 365,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

PRESET_USERS = [
    ('asadbek', '20110903'), ("og'abek", "20110528"), ('farhod', '20110414'),
    ('akmal', '20110923'), ('namoz', '20120928'),
]
DEFAULT_DATA = {'tasks': [], 'notes': [], 'events': [], 'goals': [], 'preferences': {'focusMinutes': 25}}

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            avatar_data TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        # Migrate databases created by the first Classroom version.
        cols = {row['name'] for row in conn.execute('PRAGMA table_info(users)')}
        if 'display_name' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        if 'avatar_data' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN avatar_data TEXT NOT NULL DEFAULT ''")
        conn.execute('''CREATE TABLE IF NOT EXISTS user_data (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            payload TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        for username, password in PRESET_USERS:
            if not conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
                conn.execute('INSERT INTO users (username,password_hash,display_name) VALUES (?,?,?)',
                             (username, generate_password_hash(password), username))

def clean_username(value):
    return (value or '').strip().lower()

def current_user():
    if 'user_id' not in session:
        return None
    with db() as conn:
        return conn.execute('SELECT id, username, display_name, avatar_data FROM users WHERE id=?',
                            (session['user_id'],)).fetchone()

def require_user():
    user = current_user()
    if not user:
        return None, (jsonify(message='Sessiya tugagan. Qayta kiring.'), 401)
    return user, None

@app.get('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.get('/api/me')
def me():
    user, error = require_user()
    if error: return error
    return jsonify(username=user['username'], displayName=user['display_name'] or user['username'], avatar=user['avatar_data'])

@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    username = clean_username(data.get('username'))
    password = (data.get('password') or '').lower()
    if not username or not password:
        return jsonify(message='Username va parolni kiriting.'), 400
    with db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify(message='Username yoki parol noto‘g‘ri.'), 401
    session.clear(); session.permanent = True; session['user_id'] = user['id']
    return jsonify(username=user['username'], displayName=user['display_name'] or user['username'], avatar=user['avatar_data'])

@app.post('/api/signup')
def signup():
    data = request.get_json(silent=True) or {}
    username = clean_username(data.get('username'))
    password = (data.get('password') or '').lower()
    confirm = (data.get('confirmPassword') or '').lower()
    if not re.fullmatch(r"[a-z0-9_'.-]{3,24}", username):
        return jsonify(message='Username 3–24 belgidan iborat bo‘lsin (harf, raqam, _ . -).'), 400
    if len(password) < 6: return jsonify(message='Parol kamida 6 ta belgidan iborat bo‘lishi kerak.'), 400
    if password != confirm: return jsonify(message='Parollar mos kelmadi.'), 400
    time.sleep(1.2)
    try:
        with db() as conn:
            cur = conn.execute('INSERT INTO users (username,password_hash,display_name) VALUES (?,?,?)',
                               (username, generate_password_hash(password), username))
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(message='Bu username band. Boshqasini tanlang.'), 409
    session.clear(); session.permanent = True; session['user_id'] = user_id
    return jsonify(username=username, displayName=username, avatar=''), 201

@app.get('/api/data')
def get_data():
    user, error = require_user()
    if error: return error
    with db() as conn:
        row = conn.execute('SELECT payload FROM user_data WHERE user_id=?', (user['id'],)).fetchone()
    try: payload = json.loads(row['payload']) if row else DEFAULT_DATA.copy()
    except (ValueError, TypeError): payload = DEFAULT_DATA.copy()
    for key, value in DEFAULT_DATA.items(): payload.setdefault(key, value)
    return jsonify(payload)

@app.put('/api/data')
def save_data():
    user, error = require_user()
    if error: return error
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict): return jsonify(message='Ma’lumot formati noto‘g‘ri.'), 400
    # Keep only known data collections and enforce reasonable limits.
    clean = {}
    for key, limit in [('tasks', 500), ('notes', 500), ('events', 500), ('goals', 200)]:
        value = payload.get(key, [])
        if not isinstance(value, list) or len(value) > limit:
            return jsonify(message=f'{key} ma’lumotlari noto‘g‘ri yoki limitdan oshdi.'), 400
        clean[key] = value
    prefs = payload.get('preferences', {})
    if not isinstance(prefs, dict): prefs = {}
    clean['preferences'] = {'focusMinutes': max(1, min(180, int(prefs.get('focusMinutes', 25) or 25)))}
    encoded = json.dumps(clean, ensure_ascii=False)
    with db() as conn:
        conn.execute('INSERT INTO user_data(user_id,payload,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) '
                     'ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload, updated_at=CURRENT_TIMESTAMP',
                     (user['id'], encoded))
    return jsonify(saved=True)

@app.put('/api/profile')
def update_profile():
    user, error = require_user()
    if error: return error
    data = request.get_json(silent=True) or {}
    display_name = (data.get('displayName') or '').strip()
    avatar = data.get('avatar') or ''
    if not display_name or len(display_name) > 40:
        return jsonify(message='Ism 1–40 belgidan iborat bo‘lsin.'), 400
    if avatar and (not isinstance(avatar, str) or not re.match(r'^data:image/(png|jpeg|webp);base64,', avatar) or len(avatar) > 1_500_000):
        return jsonify(message='Rasm PNG, JPG yoki WEBP bo‘lsin va hajmi 1 MB dan oshmasin.'), 400
    with db() as conn:
        conn.execute('UPDATE users SET display_name=?, avatar_data=? WHERE id=?',
                     (display_name, avatar, user['id']))
    return jsonify(displayName=display_name, avatar=avatar)

@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify(message='Hisobdan chiqdingiz.')

@app.errorhandler(413)
def too_large(_):
    return jsonify(message='Yuborilgan ma’lumot juda katta.'), 413

init_db()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)), debug=os.environ.get('FLASK_DEBUG', '0') == '1')
