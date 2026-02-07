from flask import Flask, jsonify, request, render_template, send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import blockchain
import os
import io
import qrcode
from PIL import Image
from functools import wraps
import hashlib
import hmac
import logging
import json
from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agriyogi.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SECURE_COOKIES', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; font-src cdn.jsdelivr.net"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad request: {request.path} - {error}")
    return jsonify({'error': 'bad_request', 'message': str(error)}), 400


@app.errorhandler(401)
def unauthorized(error):
    logger.warning(f"Unauthorized access attempt: {request.path}")
    return jsonify({'error': 'unauthorized', 'message': 'Authentication required'}), 401


@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"Forbidden access attempt: {request.path}")
    return jsonify({'error': 'forbidden', 'message': 'Access denied'}), 403


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'not_found', 'message': 'Endpoint not found'}), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {request.path} from {get_remote_address()}")
    return jsonify({'error': 'rate_limit_exceeded', 'message': 'Too many requests'}), 429


@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {error}", exc_info=True)
    return jsonify({'error': 'server_error', 'message': 'Internal server error'}), 500


def validate_input(data, field_name, field_type=str, max_length=5000, required=True):
    """Validate input data"""
    if required and not data:
        raise ValueError(f"{field_name} is required")
    if data and len(str(data)) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    if field_type == 'email' and data:
        if '@' not in data or '.' not in data:
            raise ValueError(f"{field_name} is not a valid email")
    return data.strip() if isinstance(data, str) else data


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path}")
            return jsonify({'error': 'authentication_required', 'message': 'Please login first'}), 401
        return f(*args, **kwargs)
    return decorated




@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/api/blocks', methods=['GET'])
def get_blocks():
    chain = blockchain.get_chain()
    result = []
    for b in chain:
        result.append({
            'index': b.index,
            'timestamp': b.timestamp,
            'data': b.data,
            'previous_hash': b.previous_hash,
            'hash': b.hash,
            'author': getattr(b, 'author', None),
            'signature': getattr(b, 'signature', None)
        })
    return jsonify(result)


@app.route('/api/mine', methods=['POST'])
def mine():
    # Require logged-in user
    if 'user' not in session:
        return jsonify({'error': 'authentication_required'}), 401
    payload = request.get_json() or {}
    data = payload.get('data', 'No data')
    new_block = blockchain.add_block(data)
    # sign block using user's hmac key
    key = blockchain.get_user_hmac_key(session['user'])
    signature = None
    if key:
        signature = hmac.new(key, new_block.hash.encode(), hashlib.sha256).hexdigest()
    # persist with meta
    blockchain.save_block_with_meta(new_block, author=session['user'], signature=signature)
    return jsonify({
        'index': new_block.index,
        'timestamp': new_block.timestamp,
        'data': new_block.data,
        'previous_hash': new_block.previous_hash,
        'hash': new_block.hash,
        'author': session['user'],
        'signature': signature
    }), 201


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'authentication_required'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/qr')
def qr():
    """Return a PNG QR code for the provided `text` query param. If none provided, returns site URL."""
    text = request.args.get('text')
    if not text:
        text = request.host_url
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


@app.route('/api/register', methods=['POST'])
def register():
    payload = request.get_json() or {}
    username = payload.get('username')
    password = payload.get('password')
    if not username or not password:
        return jsonify({'error': 'missing_fields'}), 400
    ok, reason = blockchain.create_user(username, password)
    if not ok:
        return jsonify({'error': reason}), 400
    session['user'] = username
    return jsonify({'status': 'ok', 'user': username})


@app.route('/api/login', methods=['POST'])
def login():
    payload = request.get_json() or {}
    username = payload.get('username')
    password = payload.get('password')
    if blockchain.authenticate_user(username, password):
        session['user'] = username
        return jsonify({'status': 'ok', 'user': username})
    return jsonify({'error': 'invalid_credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'status': 'ok'})


@app.route('/api/verify', methods=['GET'])
def verify():
    problems = blockchain.verify_chain()
    return jsonify({'problems': problems})


if __name__ == '__main__':
    blockchain.create_initial_chain()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
