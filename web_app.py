"""
AgriYogi - Professional Farm Blockchain Platform
Production-Grade Flask Application with Security Hardening
"""

from flask import Flask, jsonify, request, render_template, send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import blockchain
import os
import io
import qrcode
from functools import wraps
import hashlib
import hmac
import logging
from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image
import base64
import requests
import json

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure structured logging
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    handlers=[
        logging.FileHandler('logs/agriyogi.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Flask app configuration
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SECURE_COOKIES', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = os.environ.get('FLASK_ENV') == 'development'
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://"
)

logger.info("AgriYogi server initializing...")

# Initialize blockchain on app startup
try:
    blockchain.create_initial_chain()
    logger.info(f"Blockchain initialized with {len(blockchain.get_chain())} blocks")
except Exception as e:
    logger.error(f"Failed to initialize blockchain: {e}", exc_info=True)


# ============================================================================
# SECURITY & MIDDLEWARE
# ============================================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "font-src cdn.jsdelivr.net; "
        "img-src 'self' data: blob:; "
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad request: {request.path} - {str(error)}")
    return jsonify({'error': 'bad_request', 'message': 'Invalid request format'}), 400


@app.errorhandler(401)
def unauthorized(error):
    logger.warning(f"Unauthorized access attempt: {request.path} from {get_remote_address()}")
    return jsonify({'error': 'unauthorized', 'message': 'Authentication required'}), 401


@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"Forbidden access attempt: {request.path} from {get_remote_address()}")
    return jsonify({'error': 'forbidden', 'message': 'Access denied'}), 403


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'not_found', 'message': 'Endpoint not found'}), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {request.path} from {get_remote_address()}")
    return jsonify({'error': 'rate_limit_exceeded', 'message': 'Too many requests. Please try again later.'}), 429


@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {str(error)}", exc_info=True)
    return jsonify({'error': 'server_error', 'message': 'Internal server error'}), 500


# ============================================================================
# UTILITIES
# ============================================================================

def validate_input(data, field_name, field_type=str, max_length=5000, required=True):
    """Validate and sanitize input data"""
    if required and not data:
        raise ValueError(f"{field_name} is required")
    
    if data and len(str(data)) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    
    if field_type == 'email' and data:
        if '@' not in data or '.' not in data or len(data) > 255:
            raise ValueError(f"{field_name} is not a valid email")
    
    if field_type == 'username' and data:
        if len(data) < 3 or len(data) > 50:
            raise ValueError(f"Username must be 3-50 characters")
        if not data.replace('_', '').replace('-', '').isalnum():
            raise ValueError(f"Username can only contain letters, numbers, underscore, and hyphen")
    
    if isinstance(data, str):
        return data.strip()
    return data


def login_required(f):
    """Decorator to require login for an endpoint"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path} from {get_remote_address()}")
            return jsonify({'error': 'authentication_required', 'message': 'Please login first'}), 401
        return f(*args, **kwargs)
    return decorated


def compress_image(file_data, max_width=400, max_height=400, quality=75):
    """Compress and resize image to reduce file size"""
    try:
        img = Image.open(io.BytesIO(file_data))
        # Convert RGBA to RGB if needed
        if img.mode == 'RGBA':
            rgb_img = Image.new('RGB', img.size, (255, 255, 255))
            rgb_img.paste(img, mask=img.split()[3] if len(img.split()) == 4 else None)
            img = rgb_img
        # Resize maintaining aspect ratio
        img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        # Save as JPEG with compression
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=quality, optimize=True)
        return output.getvalue()
    except Exception as e:
        logger.warning(f"Image compression failed: {e}. Using original.")
        return file_data


# ============================================================================
# ROUTES - PUBLIC
# ============================================================================

@app.route('/')
def index():
    """Render main dashboard"""
    try:
        logger.info(f"Dashboard accessed from {get_remote_address()}")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering dashboard: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Failed to load dashboard'}), 500


@app.route('/signup')
def signup():
    """Render signup page"""
    try:
        logger.info(f"Signup page accessed from {get_remote_address()}")
        return render_template('signup.html')
    except Exception as e:
        logger.error(f"Error rendering signup: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Failed to load signup page'}), 500


@app.route('/health')
def health():
    """Health check endpoint for monitoring"""
    try:
        # Quick database check
        chain = blockchain.get_chain()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'blockchain_length': len(chain)
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503


@app.route('/api/weather/today', methods=['GET'])
def weather_today():
    """Fetch live weather from Open-Meteo (no API key required)"""
    try:
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        if lat is None or lon is None:
            return jsonify({'error': 'missing_location', 'message': 'lat and lon are required'}), 400

        url = 'https://api.open-meteo.com/v1/forecast'
        params = {
            'latitude': lat,
            'longitude': lon,
            'current': 'temperature_2m,relative_humidity_2m,precipitation,wind_speed_10m',
            'timezone': 'auto'
        }
        resp = requests.get(url, params=params, timeout=15)
        if resp.status_code != 200:
            logger.warning(f"Open-Meteo error: {resp.status_code} {resp.text[:200]}")
            return jsonify({'error': 'upstream_error', 'message': 'Weather provider error'}), 502

        data = resp.json()
        current = data.get('current', {})

        return jsonify({
            'temperature': current.get('temperature_2m'),
            'humidity': current.get('relative_humidity_2m'),
            'wind': current.get('wind_speed_10m'),
            'rainfall': current.get('precipitation'),
            'notes': '',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Weather endpoint error: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Weather unavailable'}), 500


@app.route('/api/satellite/ndvi', methods=['GET'])
def satellite_ndvi():
    """Return NDVI image URL. Sentinel Hub required; not available via Planet basemaps."""
    try:
        instance_id = os.environ.get('SENTINEL_INSTANCE_ID')
        if not instance_id:
            return jsonify({'error': 'ndvi_unavailable', 'message': 'NDVI requires Sentinel Hub instance ID'}), 501

        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        if lat is None or lon is None:
            return jsonify({'error': 'missing_location', 'message': 'lat and lon are required'}), 400

        delta = float(os.environ.get('SENTINEL_BBOX_DELTA', '0.002'))
        bbox = f"{lon - delta},{lat - delta},{lon + delta},{lat + delta}"
        end = datetime.utcnow().strftime('%Y-%m-%d')
        start = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)).strftime('%Y-%m-%d')
        time_range = f"{start}/{end}"

        base = f"https://services.sentinel-hub.com/ogc/wms/{instance_id}"
        params = (
            f"SERVICE=WMS&REQUEST=GetMap&VERSION=1.3.0"
            f"&LAYERS=NDVI&FORMAT=image/png&CRS=EPSG:4326"
            f"&BBOX={bbox}&WIDTH=512&HEIGHT=512&TIME={time_range}"
        )
        image_url = f"{base}?{params}"

        return jsonify({
            'image_url': image_url,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"NDVI endpoint error: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'NDVI unavailable'}), 500


@app.route('/api/satellite/imagery', methods=['GET'])
def satellite_imagery():
    """Return true-color satellite image URL.
    Uses Planet basemaps if PLANET_API_KEY is set; otherwise Sentinel Hub.
    """
    try:
        planet_key = os.environ.get('PLANET_API_KEY')
        if planet_key:
            lat = request.args.get('lat', type=float)
            lon = request.args.get('lon', type=float)
            if lat is None or lon is None:
                return jsonify({'error': 'missing_location', 'message': 'lat and lon are required'}), 400

            # Fetch latest Planet basemap mosaic
            mosaics_url = "https://api.planet.com/basemaps/v1/mosaics"
            resp = requests.get(mosaics_url, auth=(planet_key, ""), timeout=20)
            if resp.status_code != 200:
                logger.warning(f"Planet basemaps error: {resp.status_code} {resp.text[:200]}")
                return jsonify({'error': 'upstream_error', 'message': 'Planet basemaps error'}), 502

            mosaics = resp.json().get("mosaics", [])
            if not mosaics:
                return jsonify({'error': 'no_mosaics', 'message': 'No Planet mosaics available'}), 502

            latest = mosaics[0]
            tiles_template = latest.get("_links", {}).get("tiles")
            if not tiles_template:
                return jsonify({'error': 'tiles_unavailable', 'message': 'Planet tiles URL not available'}), 502

            # Compute tile x/y for zoom level 12
            zoom = 12
            import math
            lat_rad = math.radians(lat)
            n = 2.0 ** zoom
            x = int((lon + 180.0) / 360.0 * n)
            y = int((1.0 - math.log(math.tan(lat_rad) + (1 / math.cos(lat_rad))) / math.pi) / 2.0 * n)

            image_url = tiles_template.replace("{z}", str(zoom)).replace("{x}", str(x)).replace("{y}", str(y))
            return jsonify({
                'image_url': image_url,
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'PLANET_BASEMAPS'
            }), 200

        instance_id = os.environ.get('SENTINEL_INSTANCE_ID')
        if not instance_id:
            return jsonify({'error': 'missing_instance', 'message': 'SENTINEL_INSTANCE_ID not set'}), 400

        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        if lat is None or lon is None:
            return jsonify({'error': 'missing_location', 'message': 'lat and lon are required'}), 400

        delta = float(os.environ.get('SENTINEL_BBOX_DELTA', '0.002'))
        bbox = f"{lon - delta},{lat - delta},{lon + delta},{lat + delta}"
        end = datetime.utcnow().strftime('%Y-%m-%d')
        start = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)).strftime('%Y-%m-%d')
        time_range = f"{start}/{end}"

        base = f"https://services.sentinel-hub.com/ogc/wms/{instance_id}"
        params = (
            f"SERVICE=WMS&REQUEST=GetMap&VERSION=1.3.0"
            f"&LAYERS=TRUE_COLOR&FORMAT=image/png&CRS=EPSG:4326"
            f"&BBOX={bbox}&WIDTH=512&HEIGHT=512&TIME={time_range}"
        )
        image_url = f"{base}?{params}"

        return jsonify({
            'image_url': image_url,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Imagery endpoint error: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Imagery unavailable'}), 500


@app.route('/api/openet/et', methods=['GET'])
def openet_et():
    """Fetch ET from OpenET API (requires env configuration).
    If not configured, fall back to NASA POWER daily ET (no key).
    """
    try:
        api_url = os.environ.get('OPENET_API_URL')
        api_key = os.environ.get('OPENET_API_KEY')

        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        if lat is None or lon is None:
            return jsonify({'error': 'missing_location', 'message': 'lat and lon are required'}), 400

        if api_url and api_key:
            params = {'lat': lat, 'lon': lon, 'key': api_key}
            resp = requests.get(api_url, params=params, timeout=20)
            if resp.status_code != 200:
                logger.warning(f"OpenET error: {resp.status_code} {resp.text[:200]}")
                return jsonify({'error': 'upstream_error', 'message': 'OpenET provider error'}), 502

            payload = resp.json()
            return jsonify(payload), 200

        # Fallback: NASA POWER (no API key)
        power_url = "https://power.larc.nasa.gov/api/temporal/daily/point"
        today = datetime.utcnow().strftime('%Y%m%d')
        params = {
            "latitude": lat,
            "longitude": lon,
            "parameters": "EVPTRNS",  # evapotranspiration
            "community": "AG",
            "format": "JSON",
            "start": today,
            "end": today
        }
        resp = requests.get(power_url, params=params, timeout=20)
        if resp.status_code != 200:
            logger.warning(f"NASA POWER error: {resp.status_code} {resp.text[:200]}")
            return jsonify({'error': 'upstream_error', 'message': 'NASA POWER error'}), 502

        payload = resp.json()
        values = payload.get("properties", {}).get("parameter", {}).get("EVPTRNS", {})
        # take the latest available date
        latest_date = sorted(values.keys())[-1] if values else None
        et_value = values.get(latest_date) if latest_date else None
        return jsonify({
            "et_mm": et_value,
            "timestamp": latest_date,
            "source": "NASA_POWER"
        }), 200
    except Exception as e:
        logger.error(f"OpenET endpoint error: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'ET unavailable'}), 500


@app.route('/qr')
@limiter.limit("60 per minute")
def qr():
    """Generate QR code from text parameter"""
    try:
        text = request.args.get('text', '').strip()
        if not text:
            text = request.host_url
        
        if len(text) > 2953:  # QR code limit
            return jsonify({'error': 'text_too_long'}), 400
        
        logger.info(f"QR code generated for: {text[:50]}...")
        
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png')
    except Exception as e:
        logger.error(f"QR generation error: {e}", exc_info=True)
        return jsonify({'error': 'qr_generation_failed'}), 500


# ============================================================================
# ROUTES - API (BLOCKCHAIN)
# ============================================================================

@app.route('/api/blocks', methods=['GET'])
@limiter.limit("100 per minute")
def get_blocks():
    """Retrieve all blockchain blocks with pagination support"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        
        # Validate pagination
        if page < 1 or per_page < 1 or per_page > 100:
            return jsonify({'error': 'invalid_pagination'}), 400
        
        chain = blockchain.get_chain()
        total = len(chain)
        
        # Pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_chain = chain[start:end]
        
        result = []
        for b in paginated_chain:
            result.append({
                'index': b.index,
                'timestamp': b.timestamp,
                'data': b.data,
                'previous_hash': b.previous_hash,
                'hash': b.hash,
                'author': getattr(b, 'author', None),
                'signature': getattr(b, 'signature', None),
                'photo_base64': getattr(b, 'photo_base64', None),
                'verified_by': getattr(b, 'verified_by', None)
            })
        
        logger.info(f"Blocks retrieved: page {page}, total {total}")
        
        return jsonify({
            'blocks': result,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving blocks: {e}", exc_info=True)
        return jsonify({'error': 'server_error'}), 500


@app.route('/api/mine', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def mine():
    """Add a new block to the blockchain (requires login)"""
    try:
        # Handle both JSON and multipart/form-data
        if request.is_json:
            payload = request.get_json() or {}
            data = payload.get('data', '').strip()
            photo_base64 = payload.get('photo_base64', None)
            verified_by = payload.get('verified_by', '').strip() or None
        else:
            data = request.form.get('data', '').strip()
            verified_by = request.form.get('verified_by', '').strip() or None
            photo_base64 = None
            
            # Handle file upload
            if 'photo' in request.files:
                file = request.files['photo']
                if file and file.filename:
                    file_data = file.read()
                    # Compress image to reduce size
                    compressed_data = compress_image(file_data)
                    photo_base64 = base64.b64encode(compressed_data).decode('utf-8')
                    original_size = len(file_data) / 1024
                    compressed_size = len(compressed_data) / 1024
                    logger.info(f"Photo compressed: {original_size:.1f}KB → {compressed_size:.1f}KB")
        
        # Input validation
        if not data:
            return jsonify({'error': 'empty_data', 'message': 'Block data cannot be empty'}), 400
        
        data = validate_input(data, 'Block data', max_length=5000)
        if verified_by:
            verified_by = validate_input(verified_by, 'Verified by', max_length=100)
        
        logger.info(f"Mining new block by user: {session['user']}")

        new_block = blockchain.add_block(data)
        
        # Sign block with user's HMAC key
        key = blockchain.get_user_hmac_key(session['user'])
        signature = None
        if key:
            signature = hmac.new(key, new_block.hash.encode(), hashlib.sha256).hexdigest()
        
        # Persist with metadata
        blockchain.save_block_with_meta(new_block, author=session['user'], signature=signature,
                                        photo_base64=photo_base64, verified_by=verified_by)
        
        logger.info(f"Block #{new_block.index} created by {session['user']}")
        
        return jsonify({
            'index': new_block.index,
            'timestamp': new_block.timestamp,
            'data': new_block.data,
            'previous_hash': new_block.previous_hash,
            'hash': new_block.hash,
            'author': session['user'],
            'signature': signature,
            'photo_base64': photo_base64,
            'verified_by': verified_by
        }), 201
    except ValueError as e:
        logger.warning(f"Validation error in mine: {e}")
        return jsonify({'error': 'validation_error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error mining block: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Failed to create block'}), 500


@app.route('/api/verify', methods=['GET'])
@limiter.limit("60 per minute")
def verify():
    """Verify blockchain integrity"""
    try:
        logger.info("Blockchain verification requested")
        problems = blockchain.verify_chain()
        
        is_valid = len(problems) == 0
        logger.info(f"Verification complete. Valid: {is_valid}, Problems: {len(problems)}")
        
        return jsonify({
            'valid': is_valid,
            'problems': problems,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Error verifying blockchain: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Verification failed'}), 500


# ============================================================================
# ROUTES - API (SENSORS)
# ============================================================================

SENSORS_FILE = os.path.join(os.path.dirname(__file__), 'latest_sensors.json')


def save_latest_sensors(payload):
    with open(SENSORS_FILE, 'w', encoding='utf-8') as f:
        json.dump(payload, f)


def load_latest_sensors():
    if not os.path.exists(SENSORS_FILE):
        return None
    with open(SENSORS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


@app.route('/api/sensors/ingest', methods=['POST'])
def sensors_ingest():
    """Ingest latest sensor readings from Pico (no auth)"""
    try:
        payload = request.get_json() or {}
        if not payload:
            return jsonify({'error': 'empty_payload'}), 400

        payload['received_at'] = datetime.utcnow().isoformat()
        save_latest_sensors(payload)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.error(f"Sensor ingest error: {e}", exc_info=True)
        return jsonify({'error': 'server_error'}), 500


@app.route('/api/sensors/latest', methods=['GET'])
def sensors_latest():
    """Return latest sensor readings"""
    try:
        data = load_latest_sensors()
        if not data:
            return jsonify({'status': 'empty'}), 200
        normalized = {
            'device_id': data.get('device_id'),
            'timestamp': data.get('timestamp'),
            'received_at': data.get('received_at'),
            'temperature': data.get('temperature'),
            'humidity': data.get('humidity'),
            'soil_moisture': data.get('soil_moisture'),
            'soil_raw': data.get('soil_raw'),
            'degradation_touch': data.get('degradation_touch')
        }
        return jsonify(normalized), 200
    except Exception as e:
        logger.error(f"Sensor latest error: {e}", exc_info=True)
        return jsonify({'error': 'server_error'}), 500


# ============================================================================
# ROUTES - API (AUTHENTICATION)
# ============================================================================

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user account"""
    try:
        payload = request.get_json() or {}
        username = payload.get('username', '').strip()
        password = payload.get('password', '').strip()
        
        # Input validation
        if not username:
            return jsonify({'error': 'missing_username'}), 400
        if not password:
            return jsonify({'error': 'missing_password'}), 400
        
        username = validate_input(username, 'Username', field_type='username', max_length=50)
        password = validate_input(password, 'Password', max_length=128)
        
        if len(password) < 6:
            return jsonify({'error': 'password_too_short', 'message': 'Password must be at least 6 characters'}), 400
        
        logger.info(f"Registration attempt for user: {username} from {get_remote_address()}")
        
        ok, reason = blockchain.create_user(username, password)
        if not ok:
            logger.warning(f"Registration failed for {username}: {reason}")
            return jsonify({'error': reason, 'message': f'Registration failed: {reason}'}), 400
        
        session['user'] = username
        logger.info(f"New user registered: {username}")
        
        return jsonify({'status': 'ok', 'user': username, 'message': 'Account created successfully'}), 201
    except ValueError as e:
        logger.warning(f"Validation error in register: {e}")
        return jsonify({'error': 'validation_error', 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Error registering user: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Registration failed'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and create session"""
    try:
        payload = request.get_json() or {}
        username = payload.get('username', '').strip()
        password = payload.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'missing_credentials'}), 400
        
        logger.info(f"Login attempt for user: {username} from {get_remote_address()}")
        
        if blockchain.authenticate_user(username, password):
            session['user'] = username
            logger.info(f"User logged in: {username}")
            return jsonify({'status': 'ok', 'user': username, 'message': 'Login successful'}), 200
        
        logger.warning(f"Failed login attempt for {username} from {get_remote_address()}")
        return jsonify({'error': 'invalid_credentials', 'message': 'Invalid username or password'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}", exc_info=True)
        return jsonify({'error': 'server_error', 'message': 'Login failed'}), 500


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Logout user and clear session"""
    try:
        user = session.get('user')
        session.pop('user', None)
        logger.info(f"User logged out: {user}")
        return jsonify({'status': 'ok', 'message': 'Logged out successfully'}), 200
    except Exception as e:
        logger.error(f"Error during logout: {e}", exc_info=True)
        return jsonify({'error': 'server_error'}), 500


@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user information"""
    try:
        return jsonify({
            'user': session.get('user'),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Error getting current user: {e}", exc_info=True)
        return jsonify({'error': 'server_error'}), 500


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info(f"Starting AgriYogi server on port {port} (debug={debug})")
    app.run(host='0.0.0.0', port=port, debug=debug)
