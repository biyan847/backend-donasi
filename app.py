import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
import jwt
from functools import wraps
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import random

load_dotenv()
app = Flask(__name__,static_url_path='/uploads', static_folder='uploads')

# Konfigurasi email Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'febyanputra456@gmail.com'     # GANTI
app.config['MAIL_PASSWORD'] = 'blxu jiji mjnn ndof'          # GANTI
mail = Mail(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_PROFILE_FOLDER = 'uploads/profiles'
UPLOAD_BANNER_FOLDER = 'uploads/banners'
UPLOAD_CAMPAIGN_FOLDER = 'uploads/campaigns'




app.config['UPLOAD_CAMPAIGN_FOLDER'] = UPLOAD_CAMPAIGN_FOLDER
app.config['UPLOAD_PROFILE_FOLDER'] = UPLOAD_PROFILE_FOLDER
app.config['UPLOAD_BANNER_FOLDER'] = UPLOAD_BANNER_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY")

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            database=os.getenv("DB_NAME")
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

def token_required(role="user"):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                parts = request.headers['Authorization'].split()
                if len(parts) == 2 and parts[0].lower() == "bearer":
                    token = parts[1]
            if not token:
                return jsonify({"message": "Token is missing!"}), 401
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                if role == "admin" and "admin_id" not in data:
                    return jsonify({"message": "Admin access required"}), 403
                if role == "user" and "user_id" not in data:
                    return jsonify({"message": "User access required"}), 403
                current_user = data
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token expired!"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"message": "Token is invalid!"}), 401
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

# ========== USER ==========

@app.route('/api/users/register', methods=['POST'])
def user_register():
    data = request.json
    if not data or not all(k in data for k in ("username", "email", "password")):
        return jsonify({"message": "Missing required fields"}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (data['email'],))
            if cursor.fetchone():
                return jsonify({"message": "Email already registered"}), 409
            hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (data['username'], data['email'], hashed_pw))
            conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

@app.route('/api/users/login', methods=['POST'])
def user_login():
    data = request.json
    if not data or not all(k in data for k in ("email", "password")):
        return jsonify({"message": "Missing required fields"}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (data['email'],))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404
            if bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
                token = jwt.encode(
                    {"user_id": user["id"], "role": "user"},
                    SECRET_KEY,
                    algorithm="HS256"
                )
                return jsonify({"message": "Login successful", "token": token}), 200
            else:
                return jsonify({"message": "Invalid credentials"}), 401
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()


@app.route('/api/users/profile', methods=['GET'])
@token_required(role="user")
def user_profile(current_user):
    user_id = current_user['user_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username, email, full_name, profile_photo, banner_image, location FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if user:
                return jsonify({"user": user})
            else:
                return jsonify({"message": "User not found"}), 404
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

# ===== USER PROFILE UPDATE & UPLOAD =====

@app.route('/api/users/profile/update', methods=['POST'])
@token_required(role="user")
def update_user_profile(current_user):
    user_id = current_user['user_id']

    first_name = request.form.get('firstName')
    last_name = request.form.get('lastName')
    email = request.form.get('email')
    location = request.form.get('location')

    profile_file = request.files.get('profilePhoto')
    banner_file = request.files.get('bannerImage')

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        profile_filename = None
        banner_filename = None

        if profile_file and allowed_file(profile_file.filename):
            filename = secure_filename(profile_file.filename)
            profile_filename = f"user_{user_id}_profile_{filename}"
            path = os.path.join(app.config['UPLOAD_PROFILE_FOLDER'], profile_filename)
            os.makedirs(app.config['UPLOAD_PROFILE_FOLDER'], exist_ok=True)
            profile_file.save(path)

        if banner_file and allowed_file(banner_file.filename):
            filename = secure_filename(banner_file.filename)
            banner_filename = f"user_{user_id}_banner_{filename}"
            path = os.path.join(app.config['UPLOAD_BANNER_FOLDER'], banner_filename)
            os.makedirs(app.config['UPLOAD_BANNER_FOLDER'], exist_ok=True)
            banner_file.save(path)

        with conn.cursor() as cursor:
            sql = """UPDATE users SET full_name=%s, email=%s, location=%s"""
            params = [
                f"{first_name} {last_name}" if first_name and last_name else None,
                email,
                location
            ]

            if profile_filename:
                sql += ", profile_photo=%s"
                params.append(profile_filename)
            if banner_filename:
                sql += ", banner_image=%s"
                params.append(banner_filename)

            sql += " WHERE id=%s"
            params.append(user_id)

            cursor.execute(sql, tuple(params))
            conn.commit()

        # 🔁 Ambil ulang data user terbaru untuk dikirim ke frontend
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT id, username, email, full_name, profile_photo, banner_image, location
                FROM users
                WHERE id = %s
            """, (user_id,))
            updated_user = cursor.fetchone()

        return jsonify({
            "message": "User profile updated successfully",
            "user": updated_user
        }), 200

    except Exception as e:
        print(f"Error updating user profile: {e}")
        return jsonify({"message": "Failed to update user profile"}), 500
    finally:
        conn.close()



# ========== ADMIN ==========

@app.route('/api/admins/register', methods=['POST'])
def admin_register():
    data = request.json
    if not data or not all(k in data for k in ("username", "email", "password")):
        return jsonify({"message": "Missing required fields"}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM admins WHERE email = %s", (data['email'],))
            if cursor.fetchone():
                return jsonify({"message": "Email already registered"}), 409
            hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO admins (username, email, password) VALUES (%s, %s, %s)",
                           (data['username'], data['email'], hashed_pw))
            conn.commit()
        return jsonify({"message": "Admin created successfully"}), 201
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

@app.route('/api/admins/login', methods=['POST'])
def admin_login():
    data = request.json
    if not data or not all(k in data for k in ("email", "password")):
        return jsonify({"message": "Missing required fields"}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM admins WHERE email = %s", (data['email'],))
            admin = cursor.fetchone()
            if not admin:
                return jsonify({"message": "Admin not found"}), 404
            if bcrypt.checkpw(data['password'].encode('utf-8'), admin['password'].encode('utf-8')):
                token = jwt.encode(
                    {"admin_id": admin["id"], "role": "admin"},
                    SECRET_KEY,
                    algorithm="HS256"
                )
                return jsonify({"message": "Login successful", "token": token}), 200
            else:
                return jsonify({"message": "Invalid credentials"}), 401
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

@app.route('/api/admins/profile', methods=['GET'])
@token_required(role="admin")
def admin_profile(current_user):
    admin_id = current_user['admin_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username, email FROM admins WHERE id = %s", (admin_id,))
            admin = cursor.fetchone()
            if admin:
                return jsonify({"admin": admin})
            else:
                return jsonify({"message": "Admin not found"}), 404
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()


# ===== ADMIN PROFILE UPDATE & UPLOAD =====

@app.route('/api/admins/profile/update', methods=['POST'])
@token_required(role="admin")
def update_admin_profile(current_admin):
    admin_id = current_admin['admin_id']

    first_name = request.form.get('firstName')
    last_name = request.form.get('lastName')
    email = request.form.get('email')
    location = request.form.get('location')

    profile_file = request.files.get('profilePhoto')
    banner_file = request.files.get('bannerImage')

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        profile_filename = None
        banner_filename = None

        if profile_file and allowed_file(profile_file.filename):
            filename = secure_filename(profile_file.filename)
            profile_filename = f"admin_{admin_id}_profile_{filename}"
            path = os.path.join(app.config['UPLOAD_PROFILE_FOLDER'], profile_filename)
            os.makedirs(app.config['UPLOAD_PROFILE_FOLDER'], exist_ok=True)
            profile_file.save(path)

        if banner_file and allowed_file(banner_file.filename):
            filename = secure_filename(banner_file.filename)
            banner_filename = f"admin_{admin_id}_banner_{filename}"
            path = os.path.join(app.config['UPLOAD_BANNER_FOLDER'], banner_filename)
            os.makedirs(app.config['UPLOAD_BANNER_FOLDER'], exist_ok=True)
            banner_file.save(path)

        with conn.cursor() as cursor:
            sql = """UPDATE admins SET full_name=%s, email=%s, location=%s"""
            params = [f"{first_name} {last_name}" if first_name and last_name else None,
                      email,
                      location]

            if profile_filename:
                sql += ", profile_photo=%s"
                params.append(profile_filename)
            if banner_filename:
                sql += ", banner_image=%s"
                params.append(banner_filename)
            sql += " WHERE id=%s"
            params.append(admin_id)

            cursor.execute(sql, tuple(params))
            conn.commit()

        return jsonify({"message": "Admin profile updated successfully"})
    except Exception as e:
        print(f"Error updating admin profile: {e}")
        return jsonify({"message": "Failed to update admin profile"}), 500
    finally:
        conn.close()

# ========== CAMPAIGN ==========

@app.route('/api/campaigns', methods=['POST'])
@token_required(role="user")
def create_campaign(current_user):
    user_id = current_user['user_id']

    # Ambil data text dari form
    title = request.form.get('title')
    story = request.form.get('story')
    goal_amount = request.form.get('goal_amount')
    deadline = request.form.get('deadline')
    category = request.form.get('category')
    image_file = request.files.get('image')

    if not title or not story or not goal_amount or not deadline:
        return jsonify({"message": "Missing required fields"}), 400

    image_url = None
    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        image_url = f"campaign_{user_id}_{filename}"
        path = os.path.join(app.config['UPLOAD_CAMPAIGN_FOLDER'], image_url)
        os.makedirs(app.config['UPLOAD_CAMPAIGN_FOLDER'], exist_ok=True)
        image_file.save(path)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO campaigns
                     (user_id, title, story, goal_amount, deadline, image_url, category, status)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')"""
            cursor.execute(sql, (user_id, title, story, goal_amount, deadline, image_url, category))
            conn.commit()
        return jsonify({"message": "Campaign created successfully"}), 201
    except Exception as e:
        print(f"Error creating campaign: {e}")
        return jsonify({"message": "Failed to create campaign"}), 500
    finally:
        conn.close()

@app.route('/api/campaigns', methods=['GET'])
def get_campaigns():
    token = None
    if 'Authorization' in request.headers:
        parts = request.headers['Authorization'].split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor(dictionary=True) as cursor:
            if token:
                try:
                    data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                    user_id = data.get("user_id")
                    cursor.execute("SELECT * FROM campaigns WHERE user_id = %s", (user_id,))
                except jwt.InvalidTokenError:
                    return jsonify({"message": "Invalid token"}), 401
            else:
                cursor.execute("SELECT * FROM campaigns WHERE status = 'active'")

            campaigns = cursor.fetchall()
            return jsonify(campaigns)
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Query failed"}), 500
    finally:
        conn.close()


@app.route('/api/campaigns/<int:campaign_id>', methods=['GET'])
def get_campaign_detail(campaign_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT 
                    c.*, 
                    u.full_name AS owner_name,
                    u.profile_photo AS profile_photo
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                WHERE c.id = %s
            """, (campaign_id,))
            campaign = cursor.fetchone()
            if campaign:
                return jsonify(campaign)
            else:
                return jsonify({"message": "Campaign not found"}), 404
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()


# ========== DONATION ==========

@app.route('/api/donations', methods=['POST'])
@token_required(role="user")
def create_donation(current_user):
    data = request.json
    required_fields = ["campaign_id", "amount"]
    if not data or not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400
    user_id = current_user['user_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO donations (user_id, campaign_id, amount, message)
                     VALUES (%s, %s, %s, %s)"""
            cursor.execute(sql, (
                user_id,
                data['campaign_id'],
                data['amount'],
                data.get('message')
            ))
            conn.commit()
        return jsonify({"message": "Donation successful"}), 201
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

@app.route('/api/donations/user', methods=['GET'])
@token_required(role="user")
def get_user_donations(current_user):
    user_id = current_user['user_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM donations WHERE user_id = %s", (user_id,))
            donations = cursor.fetchall()
        return jsonify(donations)
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

# ========== ADMIN CAMPAIGN MANAGEMENT ==========

@app.route('/api/admins/campaigns/<int:campaign_id>/verify', methods=['PUT'])
@token_required(role="admin")
def verify_campaign(current_admin, campaign_id):
    data = request.json
    new_status = data.get('status')
    if new_status not in ['verified', 'rejected', 'active', 'inactive']:
        return jsonify({"message": "Invalid status"}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM campaigns WHERE id = %s", (campaign_id,))
            if not cursor.fetchone():
                return jsonify({"message": "Campaign not found"}), 404
            
            cursor.execute("UPDATE campaigns SET status = %s WHERE id = %s", (new_status, campaign_id))
            conn.commit()
        return jsonify({"message": f"Campaign status updated to {new_status}"}), 200
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

@app.route('/api/admins/campaigns/<int:campaign_id>', methods=['PUT'])
@token_required(role="admin")
def update_campaign(current_admin, campaign_id):
    data = request.json
    fields = []
    values = []

    allowed_fields = ['title', 'story', 'goal_amount', 'deadline', 'image_url', 'category', 'status']
    for field in allowed_fields:
        if field in data:
            fields.append(f"{field} = %s")
            values.append(data[field])
    
    if not fields:
        return jsonify({"message": "No valid fields to update"}), 400
    
    values.append(campaign_id)

    sql = f"UPDATE campaigns SET {', '.join(fields)} WHERE id = %s"

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM campaigns WHERE id = %s", (campaign_id,))
            if not cursor.fetchone():
                return jsonify({"message": "Campaign not found"}), 404
            
            cursor.execute(sql, tuple(values))
            conn.commit()
        return jsonify({"message": "Campaign updated successfully"}), 200
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

@app.route('/api/admins/campaigns/<int:campaign_id>', methods=['DELETE'])
@token_required(role="admin")
def delete_campaign(current_admin, campaign_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM campaigns WHERE id = %s", (campaign_id,))
            if not cursor.fetchone():
                return jsonify({"message": "Campaign not found"}), 404

            # Hapus data donasi dulu
            cursor.execute("DELETE FROM donations WHERE campaign_id = %s", (campaign_id,))

            # Baru hapus campaign
            cursor.execute("DELETE FROM campaigns WHERE id = %s", (campaign_id,))
            conn.commit()
        return jsonify({"message": "Campaign deleted successfully"}), 200
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": str(err)}), 500
    finally:
        conn.close()

@app.route('/api/admins/campaigns', methods=['GET'])
@token_required(role="admin")
def get_all_campaigns_for_admin(current_admin):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT 
                    c.*, 
                    u.full_name AS owner_name,
                    u.profile_photo AS profile_photo
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                ORDER BY c.id DESC
            """)
            campaigns = cursor.fetchall()
            return jsonify(campaigns), 200
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": str(err)}), 500

    finally:
        conn.close()
@app.route('/api/admins/campaigns/<int:campaign_id>', methods=['GET'])
@token_required(role="admin")
def get_campaign_detail_for_admin(current_admin, campaign_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT 
                    c.*, 
                    u.full_name AS owner_name,
                    u.profile_photo AS profile_photo
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                WHERE c.id = %s
            """, (campaign_id,))
            campaign = cursor.fetchone()

        if not campaign:
            return jsonify({"message": "Campaign not found"}), 404

        return jsonify(campaign), 200

    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500

    finally:
        conn.close()


#send otp
@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')
    otp = str(random.randint(100000, 999999))

    print(">>> EMAIL:", email)
    print(">>> OTP:", otp)

    if not email:
        return jsonify({"message": "Email is required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "REPLACE INTO otp_codes (email, otp) VALUES (%s, %s)",
                (email, otp)
            )
            conn.commit()

        # Kirim email
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP code is: {otp}'
        mail.send(msg)

        return jsonify({"message": "OTP sent successfully"}), 200

    except Exception as e:
        print(">>> ERROR sending OTP:", e)
        return jsonify({"message": "Failed to send OTP"}), 500

    finally:
        conn.close()


# Verifikasi OTP
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data['email']
    otp = data['otp']

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT otp FROM otp_codes WHERE email=%s", (email,))
            result = cursor.fetchone()

        if result and result[0] == otp:
            return jsonify({"message": "OTP verified"}), 200
        else:
            return jsonify({"message": "Invalid OTP"}), 400

    except Exception as e:
        print("Error verifying OTP:", e)
        return jsonify({"message": "Failed to verify OTP"}), 500

    finally:
        conn.close()

if __name__ == "__main__":
    app.run(debug=True)
