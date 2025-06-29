from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.message import EmailMessage
from threading import Thread
from datetime import datetime, timedelta
import secrets
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Encryption configuration
ENCRYPTION_SALT = os.getenv("ENCRYPTION_SALT").encode()
ITERATIONS = 100000

def generate_encryption_key(password: str) -> bytes:
    """Generate encryption key from password using PBKDF2HMAC"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ENCRYPTION_SALT,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class DataEncryptor:
    def __init__(self, encryption_key: str):
        self.cipher_suite = Fernet(generate_encryption_key(encryption_key))
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if data is None:
            return None
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if encrypted_data is None:
            return None
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

# PostgreSQL config
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        cursor_factory=RealDictCursor
    )

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# Security configurations
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SESSION_REFRESH_EACH_REQUEST=True
)

# CORS Configuration
CORS(app, supports_credentials=True, resources={
    r"/api/*": {
        "origins": [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            "https://veera-crt.github.io"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True,
        "max_age": 86400
    }
})

# ---------- Utility Functions ----------
def send_otp_email(to_email: str, otp: str) -> None:
    """Send OTP email using a background thread"""
    try:
        msg = EmailMessage()
        msg.set_content(f"Your OTP is: {otp}\n\nThis OTP is valid for 7 minutes.")
        msg['Subject'] = 'CybVars OTP Verification'
        msg['From'] = os.getenv("SMTP_FROM", "passkey2manager@gmail.com")
        msg['To'] = to_email

        with smtplib.SMTP_SSL(os.getenv("SMTP_HOST", "smtp.gmail.com"), 
                             int(os.getenv("SMTP_PORT", 465))) as smtp:
            smtp.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
            smtp.send_message(msg)
        logger.info(f"OTP sent to {to_email}")
    except Exception as e:
        logger.error(f"Error sending OTP email: {e}")

def get_user_encryptor(user_id: int) -> DataEncryptor:
    """Retrieve user-specific encryption key and return encryptor"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
                result = cur.fetchone()
                if not result or not result['encryption_key']:
                    raise ValueError("User encryption key not found")
                return DataEncryptor(result['encryption_key'])
    except Exception as e:
        logger.error(f"Error getting user encryptor: {e}")
        raise

# ---------- Routes ----------

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user with encrypted sensitive data"""
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify(success=False, message="Missing required fields"), 400

    email = data['email']
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Check if email exists
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return jsonify(success=False, message="Email already registered"), 409

                # Generate OTP and encryption key
                otp = f"{random.randint(100000, 999999)}"
                encryption_key = secrets.token_urlsafe(32)
                encryptor = DataEncryptor(encryption_key)

                # Encrypt sensitive data
                encrypted_phone = encryptor.encrypt_data(data.get('phone', ''))
                encrypted_address = encryptor.encrypt_data(data.get('address', ''))

                # Store user with encrypted data
                cur.execute("""
                    INSERT INTO users (
                        full_name, dob, age, email, phone, password_hash, 
                        address, latitude, longitude, otp, encryption_key
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    data.get('full_name', ''),
                    data.get('dob', ''),
                    data.get('age', ''),
                    email,
                    encrypted_phone,
                    generate_password_hash(data['password']),
                    encrypted_address,
                    data.get('latitude', 0),
                    data.get('longitude', 0),
                    otp,
                    encryption_key
                ))

                # Send OTP in background
                Thread(target=send_otp_email, args=(email, otp)).start()
                return jsonify(success=True)
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify(success=False, message="Registration failed"), 500
    
@app.route('/api/generate-otp', methods=['POST'])
def generate_otp():
    """Generate and send a new OTP for sensitive actions"""
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Generate new OTP as string (not integer)
                otp = str(random.randint(100000, 999999))
                
                # Store OTP with expiration (7 minutes)
                cur.execute("""
                    UPDATE users 
                    SET sensitive_action_otp = %s, 
                        otp_expires_at = NOW() + INTERVAL '7 minutes'
                    WHERE id = %s
                    RETURNING email, sensitive_action_otp
                """, (otp, session['user_id']))
                
                result = cur.fetchone()
                user_email = result['email']
                stored_otp = result['sensitive_action_otp']
                
                logger.info(f"Generated OTP: {otp}, Stored OTP: {stored_otp}")
                
                # Send OTP in background
                Thread(target=send_otp_email, args=(user_email, otp)).start()
                
                return jsonify(success=True, otp=otp)  # For debugging
    except Exception as e:
        logger.error(f"OTP generation failed: {e}")
        return jsonify(success=False, message="Failed to generate OTP"), 500
    
@app.route('/api/verify-action-otp', methods=['POST'])
def verify_action_otp():
    """Verify OTP for sensitive actions"""
    if 'user_id' not in session:
        logger.error("No user_id in session during OTP verification")
        return jsonify(success=False, message="Unauthorized - no session"), 401

    data = request.get_json()
    if not data or 'otp' not in data:
        logger.error("No OTP provided in request")
        return jsonify(success=False, message="Missing OTP"), 400

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                user_id = session['user_id']
                otp_input = data['otp']
                
                # Debug: Log what we're checking
                logger.info(f"Verifying OTP for user {user_id}, input: {otp_input}")
                
                # Get current OTP info
                cur.execute("""
                    SELECT sensitive_action_otp, otp_expires_at 
                    FROM users 
                    WHERE id = %s
                """, (user_id,))
                result = cur.fetchone()

                if not result:
                    logger.error("No user found for OTP verification")
                    return jsonify(success=False, message="User not found"), 404

                logger.info(f"DB OTP: {result['sensitive_action_otp']}, Expires: {result['otp_expires_at']}")

                # Check if OTP exists and is not expired
                if not result['sensitive_action_otp']:
                    logger.error("No OTP set for user")
                    return jsonify(success=False, message="No OTP generated"), 400

                if result['otp_expires_at'] < datetime.now():
                    logger.error("OTP expired")
                    return jsonify(success=False, message="OTP expired"), 400

                # Verify OTP matches
                if result['sensitive_action_otp'] != otp_input:
                    logger.error(f"OTP mismatch. DB: {result['sensitive_action_otp']}, Input: {otp_input}")
                    return jsonify(
                        success=False, 
                        message="OTP does not match"
                    ), 400

                # Generate and store action token
                action_token = secrets.token_urlsafe(32)
                cur.execute("""
                    UPDATE users 
                    SET sensitive_action_otp = NULL,
                        otp_expires_at = NULL,
                        action_token = %s,
                        action_token_expires = NOW() + INTERVAL '5 minutes'
                    WHERE id = %s
                """, (action_token, user_id))
                
                logger.info("OTP verified successfully")
                return jsonify(
                    success=True, 
                    action_token=action_token,
                    message="OTP verified successfully"
                )
    except Exception as e:
        logger.error(f"Action OTP verification failed: {str(e)}")
        return jsonify(success=False, message="OTP verification failed"), 500
    
@app.route('/api/debug-otp', methods=['GET'])
def debug_otp():
    """Debug endpoint to check current OTP state"""
    if 'user_id' not in session:
        return jsonify(success=False, message="No session"), 401
        
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT sensitive_action_otp, otp_expires_at,
                           action_token, action_token_expires
                    FROM users 
                    WHERE id = %s
                """, (session['user_id'],))
                result = cur.fetchone()
                
                return jsonify({
                    "success": True,
                    "otp": result['sensitive_action_otp'],
                    "otp_expires_at": str(result['otp_expires_at']),
                    "action_token": result['action_token'],
                    "action_token_expires": str(result['action_token_expires']),
                    "current_time": str(datetime.now())
                })
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500
    
@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and establish session"""
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify(success=False, message="Missing email or password"), 400

    email = data['email']
    password = data['password']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, password_hash, otp_verified 
                    FROM users 
                    WHERE email = %s
                """, (email,))
                user = cur.fetchone()

                if not user:
                    return jsonify(success=False, message="Email/Password are  Incorrect"), 404

                if not check_password_hash(user['password_hash'], password):
                    return jsonify(success=False, message="Email/Password are Incorrect"), 401

                # Establish secure session
                session.clear()
                session['user_id'] = user['id']
                session['email'] = email
                session['logged_in'] = True
                session.permanent = True

                return jsonify(
                    success=True, 
                    verified=user['otp_verified'],
                    user_id=user['id']
                )
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify(success=False, message="Login failed"), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear user session"""
    session.clear()
    return jsonify(success=True)

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    """Check if user is authenticated"""
    if not session.get('logged_in'):
        return jsonify(success=False, message="Not authenticated"), 401
    
    return jsonify(
        success=True,
        authenticated=True,
        user_id=session.get('user_id'),
        email=session.get('email')
    )

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP for user registration"""
    data = request.get_json()
    if not data or 'email' not in data or 'otp' not in data:
        return jsonify(success=False, message="Missing email or OTP"), 400

    email = data['email']
    otp_input = data['otp']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT otp, otp_verified 
                    FROM users 
                    WHERE email = %s
                """, (email,))
                user = cur.fetchone()

                if not user:
                    return jsonify(success=False, message="Email not found"), 404

                if user['otp_verified']:
                    return jsonify(success=False, message="Email already verified"), 400

                if user['otp'] == otp_input:
                    cur.execute("""
                        UPDATE users 
                        SET otp_verified = TRUE 
                        WHERE email = %s
                    """, (email,))
                    return jsonify(success=True)
                
                return jsonify(success=False, message="Invalid OTP"), 400
    except Exception as e:
        logger.error(f"OTP verification error: {e}")
        return jsonify(success=False, message="OTP verification failed"), 500

# Add these new routes to your existing app.py


@app.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    """Verify the password reset OTP"""
    data = request.get_json()
    if not data or 'email' not in data or 'otp' not in data:
        return jsonify(success=False, message="Email and OTP are required"), 400

    email = data['email']
    otp = data['otp']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Verify OTP
                cur.execute("""
                    SELECT id, reset_password_otp, reset_password_otp_expires
                    FROM users 
                    WHERE email = %s
                """, (email,))
                user = cur.fetchone()

                if not user:
                    return jsonify(success=False, message="User not found"), 404

                if not user['reset_password_otp'] or user['reset_password_otp'] != otp:
                    return jsonify(success=False, message="Invalid OTP"), 400

                if user['reset_password_otp_expires'] < datetime.now():
                    return jsonify(success=False, message="OTP expired"), 400

                # Generate and store reset token
                reset_token = secrets.token_urlsafe(32)
                cur.execute("""
                    UPDATE users 
                    SET reset_password_token = %s,
                        reset_password_token_expires = NOW() + INTERVAL '10 minutes'
                    WHERE id = %s
                """, (reset_token, user['id']))

                return jsonify(success=True, reset_token=reset_token)
    except Exception as e:
        logger.error(f"OTP verification failed: {e}")
        return jsonify(success=False, message="OTP verification failed"), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset user password after OTP verification"""
    data = request.get_json()
    if not data or 'email' not in data or 'new_password' not in data or 'reset_token' not in data:
        return jsonify(success=False, message="Missing required fields"), 400

    email = data['email']
    new_password = data['new_password']
    reset_token = data['reset_token']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Verify reset token
                cur.execute("""
                    SELECT id, reset_password_token, reset_password_token_expires
                    FROM users 
                    WHERE email = %s
                """, (email,))
                user = cur.fetchone()

                if not user:
                    return jsonify(success=False, message="User not found"), 404

                if not user['reset_password_token'] or user['reset_password_token'] != reset_token:
                    return jsonify(success=False, message="Invalid reset token"), 400

                if user['reset_password_token_expires'] < datetime.now():
                    return jsonify(success=False, message="Reset token expired"), 400

                # Update password and clear reset fields
                cur.execute("""
                    UPDATE users 
                    SET password_hash = %s,
                        reset_password_otp = NULL,
                        reset_password_otp_expires = NULL,
                        reset_password_token = NULL,
                        reset_password_token_expires = NULL
                    WHERE id = %s
                """, (generate_password_hash(new_password), user['id']))

                return jsonify(success=True)
    except Exception as e:
        logger.error(f"Password reset failed: {e}")
        return jsonify(success=False, message="Password reset failed"), 500

@app.route('/api/initiate-password-reset', methods=['POST'])
def initiate_password_reset():
    """Initiate password reset by verifying email and phone"""
    data = request.get_json()
    if not data or 'email' not in data or 'phone' not in data:
        return jsonify(success=False, message="Email and phone are required"), 400

    email = data['email']
    phone = data['phone']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Get user with encrypted phone number
                cur.execute("SELECT id, phone FROM users WHERE email = %s", (email,))
                user = cur.fetchone()

                if not user:
                    return jsonify(success=False, message="Failed | Email / Phone number Incorrect"), 404

                # Decrypt phone number for verification
                encryptor = get_user_encryptor(user['id'])
                decrypted_phone = encryptor.decrypt_data(user['phone'])

                if decrypted_phone != phone:
                    return jsonify(success=False, message="Failed | Email / Phone number Incorrect"), 400

                # Generate and store password reset OTP
                reset_otp = str(random.randint(100000, 999999))
                
                # First check if columns exist
                try:
                    cur.execute("""
                        UPDATE users 
                        SET reset_password_otp = %s,
                            reset_password_otp_expires = NOW() + INTERVAL '10 minutes'
                        WHERE id = %s
                        RETURNING id
                    """, (reset_otp, user['id']))
                except psycopg2.Error as e:
                    if 'column "reset_password_otp" of relation "users" does not exist' in str(e):
                        # If columns don't exist, create them
                        cur.execute("""
                            ALTER TABLE users
                            ADD COLUMN IF NOT EXISTS reset_password_otp VARCHAR(6),
                            ADD COLUMN IF NOT EXISTS reset_password_otp_expires TIMESTAMP,
                            ADD COLUMN IF NOT EXISTS reset_password_token VARCHAR(64),
                            ADD COLUMN IF NOT EXISTS reset_password_token_expires TIMESTAMP;
                        """)
                        conn.commit()
                        # Now try the update again
                        cur.execute("""
                            UPDATE users 
                            SET reset_password_otp = %s,
                                reset_password_otp_expires = NOW() + INTERVAL '10 minutes'
                            WHERE id = %s
                            RETURNING id
                        """, (reset_otp, user['id']))
                    else:
                        raise

                # Send OTP email
                Thread(target=send_otp_email, args=(email, reset_otp)).start()

                return jsonify(success=True)
    except Exception as e:
        logger.error(f"Password reset initiation failed: {e}")
        return jsonify(success=False, message="Password reset failed"), 500

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP to the user's email"""
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify(success=False, message="Missing email"), 400

    email = data['email']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE email = %s", (email,))
                if not cur.fetchone():
                    return jsonify(success=False, message="Email not registered"), 404

                otp = f"{random.randint(100000, 999999)}"
                cur.execute("""
                    UPDATE users 
                    SET otp = %s, otp_verified = FALSE, otp_expires_at = NOW() + INTERVAL '7 minutes' 
                    WHERE email = %s
                """, (otp, email))

                Thread(target=send_otp_email, args=(email, otp)).start()
                return jsonify(success=True)
    except Exception as e:
        logger.error(f"Resend OTP error: {e}")
        return jsonify(success=False, message="Failed to resend OTP"), 500

@app.route('/api/passwords', methods=['GET'])
def get_passwords():
    """Retrieve all passwords for the user with decrypted data"""
    if not session.get('logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401

    try:
        encryptor = get_user_encryptor(session['user_id'])
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, website, username, password, notes, created_at 
                    FROM passwords 
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (session['user_id'],))
                encrypted_passwords = cur.fetchall()
                
                passwords = []
                for pwd in encrypted_passwords:
                    passwords.append({
                        'id': pwd['id'],
                        'website': encryptor.decrypt_data(pwd['website']),
                        'username': encryptor.decrypt_data(pwd['username']),
                        'password': encryptor.decrypt_data(pwd['password']),
                        'notes': encryptor.decrypt_data(pwd['notes']),
                        'created_at': pwd['created_at']
                    })
                
                return jsonify(success=True, passwords=passwords)
    except Exception as e:
        logger.error(f"Error retrieving passwords: {e}")
        return jsonify(success=False, message=str(e)), 500
    
@app.route("/api/passwords/<int:password_id>", methods=["PUT"])
def update_password(password_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    data = request.get_json()
    if not data or 'action_token' not in data:
        return jsonify(success=False, message="Missing action token"), 400

    try:
        encryptor = get_user_encryptor(session['user_id'])
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Verify the action token first
                cur.execute("""
                    SELECT action_token, action_token_expires 
                    FROM users 
                    WHERE id = %s AND action_token_expires > NOW() AND action_token = %s
                """, (session['user_id'], data['action_token']))
                result = cur.fetchone()

                if not result:
                    return jsonify(success=False, message="Invalid or expired action token"), 400

                # Update the password
                cur.execute("""
                    UPDATE passwords 
                    SET website = %s,
                        username = %s,
                        password = %s,
                        notes = %s,
                        updated_at = NOW()
                    WHERE id = %s AND user_id = %s
                    RETURNING id
                """, (
                    encryptor.encrypt_data(data.get("website", "")),
                    encryptor.encrypt_data(data.get("username", "")),
                    encryptor.encrypt_data(data.get("password", "")),
                    encryptor.encrypt_data(data.get("notes", "")),
                    password_id,
                    session['user_id']
                ))
                
                if not cur.fetchone():
                    return jsonify(success=False, message="Password not found"), 404
                
                # Clear the action token after use
                cur.execute("""
                    UPDATE users 
                    SET action_token = NULL,
                        action_token_expires = NULL
                    WHERE id = %s
                """, (session['user_id'],))
                
                return jsonify(success=True)
    except Exception as e:
        logger.error(f"Password update failed: {e}")
        return jsonify(success=False, message="Update failed"), 500

@app.route('/api/passwords', methods=['POST'])
def save_password():
    """Save a new password with all sensitive data encrypted"""
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    data = request.get_json()
    if not data or 'website' not in data or 'username' not in data or 'password' not in data:
        return jsonify(success=False, message="Missing required fields"), 400
    
    try:
        encryptor = get_user_encryptor(session['user_id'])
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO passwords (
                        user_id, website, username, password, notes, created_at
                    ) VALUES (%s, %s, %s, %s, %s, NOW())
                    RETURNING id
                """, (
                    session['user_id'],
                    encryptor.encrypt_data(data['website']),
                    encryptor.encrypt_data(data['username']),
                    encryptor.encrypt_data(data['password']),
                    encryptor.encrypt_data(data.get('notes', ''))
                ))
                new_id = cur.fetchone()['id']
                return jsonify(success=True, id=new_id)
    except Exception as e:
        logger.error(f"Error saving password: {e}")
        return jsonify(success=False, message=str(e)), 500

@app.route("/api/passwords/<int:password_id>", methods=["DELETE"])
def delete_password(password_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    data = request.get_json()
    if not data or 'action_token' not in data:
        return jsonify(success=False, message="Missing action token"), 400

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Verify the action token first
                cur.execute("""
                    SELECT action_token, action_token_expires 
                    FROM users 
                    WHERE id = %s AND action_token_expires > NOW() AND action_token = %s
                """, (session['user_id'], data['action_token']))
                result = cur.fetchone()

                if not result:
                    return jsonify(success=False, message="Invalid or expired action token"), 400

                # Delete the password
                cur.execute("""
                    DELETE FROM passwords 
                    WHERE id = %s AND user_id = %s
                    RETURNING id
                """, (password_id, session['user_id']))
                
                if not cur.fetchone():
                    return jsonify(success=False, message="Password not found"), 404
                
                # Clear the action token after use
                cur.execute("""
                    UPDATE users 
                    SET action_token = NULL,
                        action_token_expires = NULL
                    WHERE id = %s
                """, (session['user_id'],))
                
                return jsonify(success=True)
    except Exception as e:
        logger.error(f"Password deletion failed: {e}")
        return jsonify(success=False, message="Deletion failed"), 500

@app.route("/api/passwords/<int:password_id>", methods=["GET"])
def get_single_password(password_id):
    """Get a single password entry with decrypted data"""
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    try:
        encryptor = get_user_encryptor(session['user_id'])
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT website, username, password, notes
                    FROM passwords
                    WHERE id = %s AND user_id = %s
                """, (password_id, session['user_id']))
                password = cur.fetchone()
                
                if not password:
                    return jsonify(success=False, message="Not found"), 404
                
                return jsonify({
                    "success": True,
                    "data": {
                        "website": encryptor.decrypt_data(password['website']),
                        "username": encryptor.decrypt_data(password['username']),
                        "password": encryptor.decrypt_data(password['password']),
                        "notes": encryptor.decrypt_data(password['notes'])
                    }
                })
    except Exception as e:
        logger.error(f"Error retrieving password: {e}")
        return jsonify(success=False, message=str(e)), 500

@app.route("/api/user-data", methods=["GET"])
def get_user_data():
    """Get user profile data with decrypted sensitive fields"""
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    try:
        encryptor = get_user_encryptor(session['user_id'])
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        full_name, dob, age, email, phone, 
                        address, latitude, longitude
                    FROM users 
                    WHERE id = %s
                """, (session['user_id'],))
                user_data = cur.fetchone()
                
                if not user_data:
                    return jsonify(success=False, message="User not found"), 404
                
                return jsonify({
                    "success": True,
                    "user_data": {
                        "full_name": user_data['full_name'],
                        "dob": user_data['dob'],
                        "age": user_data['age'],
                        "email": user_data['email'],
                        "phone": encryptor.decrypt_data(user_data['phone']),
                        "address": encryptor.decrypt_data(user_data['address']),
                        "latitude": user_data['latitude'],
                        "longitude": user_data['longitude']
                    }
                })
    except Exception as e:
        logger.error(f"Error retrieving user data: {e}")
        return jsonify(success=False, message=str(e)), 500

if __name__ == '__main__':
    required_vars = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
