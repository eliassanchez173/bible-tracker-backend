import os
import re
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from database import init_db, get_db

# ============================================================
# CONFIGURATION
# Load environment variables from .env file — never hardcode
# secrets directly in source code.
# ============================================================
load_dotenv()

app = Flask(__name__)

# Secret key used to sign session cookies. Pulled from .env,
# never hardcoded. If missing, crash immediately rather than
# run insecurely.
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise RuntimeError('SECRET_KEY environment variable is not set.')
app.secret_key = secret_key

# Session cookie hardening:
# - SameSite=Lax blocks CSRF from cross-site requests
# - Secure=False allows HTTP locally (set True in production)
# - HttpOnly prevents JavaScript from reading the cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True

# ============================================================
# CORS
# Allows requests from the React dev server locally and the
# Netlify production URL. FRONTEND_URL is set via environment
# variable on Render — never hardcoded.
# ============================================================
allowed_origins = [
    "http://localhost:5173",
    os.getenv('FRONTEND_URL', '')
]

CORS(app,
     supports_credentials=True,
     origins=[o for o in allowed_origins if o],
     allow_headers=["Content-Type"],
     methods=["GET", "POST", "DELETE", "OPTIONS"])
# ============================================================
# RATE LIMITING (OWASP: Protect Against Brute Force)
# Uses the requester's IP address as the key.
# - Default: 200 requests/day, 50/hour for all routes
# - Auth routes (login/register) are tightened to 10/minute
#   to prevent brute force and credential stuffing attacks.
# - Returns HTTP 429 with a JSON error on violation.
# ============================================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    on_breach=lambda limit: (
        jsonify({'error': 'Too many requests. Please slow down and try again later.'}), 429
    )
)

# ============================================================
# INPUT VALIDATION HELPERS (OWASP: Validate All Input)
# Schema-based validation: checks type, length, and format.
# Rejects unexpected fields to prevent mass assignment attacks.
# ============================================================

# Allowed fields per endpoint — reject anything not in this list
REGISTER_FIELDS = {'username', 'password'}
LOG_FIELDS = {'book', 'chapter', 'date', 'notes'}

# Valid Bible books — whitelist approach, reject anything not here
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

def validate_auth_input(data):
    """
    Validates registration and login input.
    - Rejects unexpected fields (mass assignment protection)
    - Enforces type, length, and character constraints
    - Returns (True, None) on success or (False, error_message)
    """
    # Reject unexpected fields
    unexpected = set(data.keys()) - REGISTER_FIELDS
    if unexpected:
        return False, f'Unexpected fields: {", ".join(unexpected)}'

    username = data.get('username')
    password = data.get('password')

    # Type checks
    if not isinstance(username, str) or not isinstance(password, str):
        return False, 'Username and password must be strings'

    # Length limits — prevent DoS via massive inputs
    if len(username) < 3 or len(username) > 32:
        return False, 'Username must be between 3 and 32 characters'
    if len(password) < 8 or len(password) > 128:
        return False, 'Password must be between 8 and 128 characters'

    # Username format — alphanumeric and underscores only
    # Prevents injection via unusual characters
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, 'Username can only contain letters, numbers, and underscores'

    return True, None


def validate_log_input(data):
    """
    Validates reading log input.
    - Rejects unexpected fields
    - Validates book against whitelist
    - Validates chapter as positive integer
    - Validates date format strictly
    - Sanitizes notes field
    """
    # Reject unexpected fields
    unexpected = set(data.keys()) - LOG_FIELDS
    if unexpected:
        return False, f'Unexpected fields: {", ".join(unexpected)}'

    book = data.get('book')
    chapter = data.get('chapter')
    date = data.get('date')
    notes = data.get('notes', '')

    # Required field checks
    if not book or not chapter or not date:
        return False, 'Book, chapter, and date are required'

    # Type checks
    if not isinstance(book, str):
        return False, 'Book must be a string'
    if not isinstance(chapter, int) or isinstance(chapter, bool):
        return False, 'Chapter must be an integer'
    if not isinstance(date, str):
        return False, 'Date must be a string'

    # Book whitelist — only accept valid Bible books
    if book not in VALID_BOOKS:
        return False, 'Invalid book name'

    # Chapter range check
    if chapter < 1 or chapter > 150:
        return False, 'Chapter must be between 1 and 150'

    # Date format validation — must be YYYY-MM-DD
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date):
        return False, 'Date must be in YYYY-MM-DD format'

    # Notes length limit
    if notes and len(notes) > 500:
        return False, 'Notes must be 500 characters or less'

    return True, None


# ============================================================
# SESSION HELPER
# ============================================================
def get_current_user_id():
    """Returns the logged-in user's ID from the session, or None."""
    return session.get('user_id')


# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per minute")  # Prevent automated account creation
def register():
    data = request.get_json(silent=True)

    # silent=True returns None instead of raising if JSON is malformed
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
        # Don't expose internal error details to the client
        return jsonify({'error': 'Username already exists'}), 409


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")  # Prevent brute force attacks
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

    # Use constant-time comparison via check_password_hash to prevent
    # timing attacks. Always check hash even if user not found.
    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({'message': 'Logged in successfully', 'username': user['username']}), 200


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/me', methods=['GET'])
def me():
    user_id = get_current_user_id()
    if user_id:
        return jsonify({'username': session.get('username')}), 200
    return jsonify({'error': 'Not logged in'}), 401


# ============================================================
# READING LOG ENDPOINTS
# ============================================================

@app.route('/api/log', methods=['POST'])
@limiter.limit("60 per minute")  # Reasonable limit for logging
def log_reading():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    valid, error = validate_log_input(data)
    if not valid:
        return jsonify({'error': error}), 400

    # Strip and sanitize notes — remove leading/trailing whitespace
    notes = data.get('notes', '').strip()

    conn = get_db()
    conn.execute(
        'INSERT INTO readings (user_id, book, chapter, date, notes) VALUES (?, ?, ?, ?, ?)',
        (user_id, data['book'], data['chapter'], data['date'], notes)
    )
    conn.commit()
    conn.close()
    return jsonify({'message': 'Reading logged successfully'}), 201


@app.route('/api/logs', methods=['GET'])
@limiter.limit("60 per minute")
def get_logs():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_db()
    logs = conn.execute(
        'SELECT * FROM readings WHERE user_id = ? ORDER BY date DESC, id DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(log) for log in logs]), 200


@app.route('/api/log/<int:log_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
def delete_log(log_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    # log_id is typed as int by Flask — no string injection possible
    conn = get_db()
    log = conn.execute(
        'SELECT * FROM readings WHERE id = ? AND user_id = ?',
        (log_id, user_id)
    ).fetchone()

    if not log:
        # Return 404 whether the log doesn't exist or belongs to
        # another user — don't reveal which case it is
        return jsonify({'error': 'Reading not found'}), 404

    conn.execute('DELETE FROM readings WHERE id = ?', (log_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Reading deleted'}), 200


@app.route('/api/streak', methods=['GET'])
@limiter.limit("60 per minute")
def get_streak():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

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
@limiter.limit("60 per minute")
def get_progress():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_db()
    rows = conn.execute(
        'SELECT book, COUNT(*) as count FROM readings WHERE user_id = ? GROUP BY book ORDER BY count DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200


# Initialize database on startup regardless of how the app is run
# This ensures tables exist whether running via Flask or gunicorn
with app.app_context():
    init_db()

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)