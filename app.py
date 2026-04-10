import os
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from database import init_db, get_db

# ============================================================
# CONFIGURATION
# ============================================================
load_dotenv()

app = Flask(__name__)

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise RuntimeError('SECRET_KEY environment variable is not set.')
app.secret_key = secret_key

jwt_secret = os.getenv('JWT_SECRET_KEY')
if not jwt_secret:
    raise RuntimeError('JWT_SECRET_KEY environment variable is not set.')
app.config['JWT_SECRET_KEY'] = jwt_secret

# JWT tokens expire after 7 days
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 60 * 60 * 24 * 7

jwt = JWTManager(app)

# ============================================================
# CORS
# ============================================================
allowed_origins = [
    "http://localhost:5173",
    os.getenv('FRONTEND_URL', '')
]

CORS(app,
     supports_credentials=True,
     origins=[o for o in allowed_origins if o],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "DELETE", "OPTIONS"])

# ============================================================
# RATE LIMITING
# ============================================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ============================================================
# INPUT VALIDATION
# ============================================================
REGISTER_FIELDS = {'username', 'password'}
LOG_FIELDS = {'book', 'chapter', 'date', 'notes'}

VALID_BOOKS = {
    'Genesis', 'Exodus', 'Leviticus', 'Numbers', 'Deuteronomy',
    'Joshua', 'Judges', 'Ruth', '1 Samuel', '2 Samuel',
    '1 Kings', '2 Kings', '1 Chronicles', '2 Chronicles',
    'Ezra', 'Nehemiah', 'Esther', 'Job', 'Psalms', 'Proverbs',
    'Ecclesiastes', 'Song of Solomon', 'Isaiah', 'Jeremiah',
    'Lamentations', 'Ezekiel', 'Daniel', 'Hosea', 'Joel', 'Amos',
    'Obadiah', 'Jonah', 'Micah', 'Nahum', 'Habakkuk', 'Zephaniah',
    'Haggai', 'Zechariah', 'Malachi', 'Matthew', 'Mark', 'Luke',
    'John', 'Acts', 'Romans', '1 Corinthians', '2 Corinthians',
    'Galatians', 'Ephesians', 'Philippians', 'Colossians',
    '1 Thessalonians', '2 Thessalonians', '1 Timothy', '2 Timothy',
    'Titus', 'Philemon', 'Hebrews', 'James', '1 Peter', '2 Peter',
    '1 John', '2 John', '3 John', 'Jude', 'Revelation'
}

def validate_log_input(data):
    unexpected = set(data.keys()) - LOG_FIELDS
    if unexpected:
        return False, f'Unexpected fields: {", ".join(unexpected)}'

    book = data.get('book')
    chapter = data.get('chapter')
    date = data.get('date')
    notes = data.get('notes', '')

    if not book or chapter is None or not date:
        return False, 'Book, chapter, and date are required'

    if not isinstance(book, str):
        return False, 'Book must be a string'

    # Chapter can now be an int (single) or list of ints (range/whole book)
    if isinstance(chapter, list):
        if not all(isinstance(c, int) and 1 <= c <= 150 for c in chapter):
            return False, 'All chapters must be integers between 1 and 150'
    elif isinstance(chapter, int) and not isinstance(chapter, bool):
        if chapter < 1 or chapter > 150:
            return False, 'Chapter must be between 1 and 150'
    else:
        return False, 'Chapter must be an integer or list of integers'

    if not isinstance(date, str):
        return False, 'Date must be a string'
    if book not in VALID_BOOKS:
        return False, 'Invalid book name'
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date):
        return False, 'Date must be in YYYY-MM-DD format'
    if notes and len(notes) > 500:
        return False, 'Notes must be 500 characters or less'

    return True, None

# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    valid, error = validate_auth_input(data)
    if not valid:
        return jsonify({'error': error}), 400
    password_hash = generate_password_hash(data['password'])
    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (data['username'], password_hash)
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Account created successfully'}), 201
    except Exception:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    valid, error = validate_auth_input(data)
    if not valid:
        return jsonify({'error': error}), 400
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?',
        (data['username'],)
    ).fetchone()
    conn.close()
    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Create JWT token — identity is the user's ID as a string
    token = create_access_token(identity=str(user['id']))
    return jsonify({
        'token': token,
        'username': user['username']
    }), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    # With JWT, logout is handled client-side by deleting the token
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/me', methods=['GET'])
@jwt_required(optional=True)
def me():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    user = conn.execute(
        'SELECT username FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'username': user['username']}), 200

# ============================================================
# READING LOG ENDPOINTS
# ============================================================

@app.route('/api/log', methods=['POST'])
@jwt_required()
@limiter.limit("60 per minute")
def log_reading():
    user_id = get_jwt_identity()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    valid, error = validate_log_input(data)
    if not valid:
        return jsonify({'error': error}), 400

    notes = data.get('notes', '').strip()
    date = data['date']
    book = data['book']
    chapter = data['chapter']

    # Normalize to always be a list
    chapters = chapter if isinstance(chapter, list) else [chapter]

    conn = get_db()
    for ch in chapters:
        conn.execute(
            'INSERT INTO readings (user_id, book, chapter, date, notes) VALUES (?, ?, ?, ?, ?)',
            (user_id, book, ch, date, notes)
        )
    conn.commit()
    conn.close()

    count = len(chapters)
    return jsonify({'message': f'{count} chapter{"s" if count > 1 else ""} logged successfully'}), 201

@app.route('/api/logs', methods=['GET'])
@jwt_required()
@limiter.limit("60 per minute")
def get_logs():
    user_id = get_jwt_identity()
    conn = get_db()
    logs = conn.execute(
        'SELECT * FROM readings WHERE user_id = ? ORDER BY date DESC, id DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(log) for log in logs]), 200

@app.route('/api/log/<int:log_id>', methods=['DELETE'])
@jwt_required()
@limiter.limit("30 per minute")
def delete_log(log_id):
    user_id = get_jwt_identity()
    conn = get_db()
    log = conn.execute(
        'SELECT * FROM readings WHERE id = ? AND user_id = ?',
        (log_id, user_id)
    ).fetchone()
    if not log:
        return jsonify({'error': 'Reading not found'}), 404
    conn.execute('DELETE FROM readings WHERE id = ?', (log_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Reading deleted'}), 200

@app.route('/api/streak', methods=['GET'])
@jwt_required()
@limiter.limit("60 per minute")
def get_streak():
    user_id = get_jwt_identity()
    conn = get_db()
    logs = conn.execute(
        'SELECT DISTINCT date FROM readings WHERE user_id = ? ORDER BY date DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    if not logs:
        return jsonify({'streak': 0}), 200
    from datetime import datetime, timedelta
    today = datetime.today().date()
    yesterday = today - timedelta(days=1)
    most_recent = datetime.strptime(logs[0]['date'], '%Y-%m-%d').date()
    if most_recent < yesterday:
        return jsonify({'streak': 0}), 200
    streak = 0
    for i, log in enumerate(logs):
        log_date = datetime.strptime(log['date'], '%Y-%m-%d').date()
        expected = most_recent - timedelta(days=i)
        if log_date == expected:
            streak += 1
        else:
            break
    return jsonify({'streak': streak}), 200

@app.route('/api/progress', methods=['GET'])
@jwt_required()
@limiter.limit("60 per minute")
def get_progress():
    user_id = get_jwt_identity()
    conn = get_db()
    rows = conn.execute(
        'SELECT book, COUNT(*) as count FROM readings WHERE user_id = ? GROUP BY book ORDER BY count DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200

# ============================================================
# STARTUP
# ============================================================
with app.app_context():
    init_db()

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)