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
import re  # Untuk validasi email kampus
import requests
from datetime import datetime
from datetime import datetime, date

load_dotenv()
app = Flask(__name__, static_url_path='/uploads', static_folder='uploads')
# Load Pinata credentials from environment variables
PINATA_API_KEY = os.getenv("PINATA_API_KEY")
PINATA_SECRET_API_KEY = os.getenv("PINATA_SECRET_API_KEY")

# Check if the PINATA API credentials are loaded correctly
if not PINATA_API_KEY or not PINATA_SECRET_API_KEY:
    raise ValueError("Pinata API credentials are missing in the environment variables.")


# Konfigurasi email Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'febyanputra456@gmail.com'  # GANTI dengan email valid
app.config['MAIL_PASSWORD'] = 'blxu jiji mjnn ndof'       # GANTI dengan password aplikasi
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


def upload_json_to_pinata(json_data):
    """
    Upload a JSON object directly to Pinata's IPFS service.
    """
    url = "https://api.pinata.cloud/pinning/pinJSONToIPFS"
    headers = {
        "Content-Type": "application/json",
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }

    response = requests.post(url, headers=headers, json=json_data)

    if response.status_code == 200:
        return response.json()  # Return the response as JSON (contains IpfsHash)
    else:
        return {"error": "Failed to upload to Pinata", "details": response.text}

def fetch_from_ipfs(cid):
    url = f"https://gateway.pinata.cloud/ipfs/{cid}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"Error fetching from IPFS: {e}")
    return None

def ensure_full_image_url(campaign):
    if campaign['image_url']:
        if not campaign['image_url'].startswith("http"):
            campaign['image_url'] = f"http://localhost:5000{campaign['image_url']}"
    return campaign


def make_url_absolute(url):
    if url and not url.startswith('http'):
        base_url = request.host_url.rstrip('/')  # Ambil URL dasar, misalnya: http://127.0.0.1:5000
        return f"{base_url}{url}"
    return url 
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

# Fungsi validasi email kampus umy.ac.id dan subdomainnya
def is_valid_campus_email(email):
    pattern = r'^[\w\.-]+@([\w-]+\.)*umy\.ac\.id$'
    return re.match(pattern, email) is not None

# ===========================
# USER ROUTES
# ===========================

@app.route('/api/users/register', methods=['POST'])
def user_register():
    data = request.json
    if not data or not all(k in data for k in ("username", "nim", "email", "password")):
        return jsonify({"message": "Missing required fields (username, nim, email, password)"}), 400

    # Validasi email kampus
    if not is_valid_campus_email(data['email']):
        return jsonify({"message": "Email harus email kampus domain umy.ac.id"}), 400

    otp = str(random.randint(100000, 999999))  # Generate OTP

    # Kirim OTP ke email
    try:
        # Simpan OTP sementara dalam database
        conn = get_db_connection()
        if not conn:
            return jsonify({"message": "Database connection failed"}), 500

        with conn.cursor() as cursor:
            cursor.execute("REPLACE INTO otp_codes (email, otp) VALUES (%s, %s)", (data['email'], otp))
            conn.commit()

        # Kirim email OTP
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[data['email']])
        msg.body = f'Your OTP code is: {otp}'
        mail.send(msg)

        return jsonify({"message": "OTP sent successfully, please verify your email to complete registration"}), 200

    except Exception as e:
        print(f"Error sending OTP: {e}")
        return jsonify({"message": "Failed to send OTP"}), 500
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

# Ganti fungsi user_profile Anda dengan yang ini

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
                # --- MULAI MODIFIKASI ---
                # Dapatkan URL dasar server, contoh: http://127.0.0.1:5000
                base_url = request.host_url.rstrip('/') 

                # Cek dan ubah path profile_photo menjadi URL lengkap
                if user.get('profile_photo') and not user['profile_photo'].startswith('http'):
                    user['profile_photo'] = f"{base_url}{user['profile_photo']}"

                # Cek dan ubah path banner_image menjadi URL lengkap
                if user.get('banner_image') and not user['banner_image'].startswith('http'):
                    user['banner_image'] = f"{base_url}{user['banner_image']}"
                # --- AKHIR MODIFIKASI ---
                
                return jsonify({"user": user})
            else:
                return jsonify({"message": "User not found"}), 404
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()
# ===== USER PROFILE UPDATE & UPLOAD =====
# Ganti fungsi update_user_profile Anda dengan yang ini

@app.route('/api/users/profile/update', methods=['POST'])
@token_required(role="user")
def update_user_profile(current_user):
    """Memperbarui profil user dan mengembalikan data dengan URL gambar yang lengkap."""
    user_id = current_user['user_id']
    
    # Ambil data dari form
    first_name = request.form.get('firstName')
    last_name = request.form.get('lastName')
    email = request.form.get('email')
    location = request.form.get('location')
    profile_file = request.files.get('profilePhoto')
    banner_file = request.files.get('bannerImage')

    profile_path = None
    banner_path = None

    # Proses simpan file avatar
    if profile_file and allowed_file(profile_file.filename):
        os.makedirs(app.config['UPLOAD_PROFILE_FOLDER'], exist_ok=True)
        filename = f"user_{user_id}_{secure_filename(profile_file.filename)}"
        save_path = os.path.join(app.config['UPLOAD_PROFILE_FOLDER'], filename)
        profile_file.save(save_path)
        profile_path = f"/{app.config['UPLOAD_PROFILE_FOLDER']}/{filename}"

    # Proses simpan file banner
    if banner_file and allowed_file(banner_file.filename):
        os.makedirs(app.config['UPLOAD_BANNER_FOLDER'], exist_ok=True)
        filename = f"banner_{user_id}_{secure_filename(banner_file.filename)}"
        save_path = os.path.join(app.config['UPLOAD_BANNER_FOLDER'], filename)
        banner_file.save(save_path)
        banner_path = f"/{app.config['UPLOAD_BANNER_FOLDER']}/{filename}"

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Koneksi database gagal"}), 500

    try:
        # Bangun query SQL secara dinamis
        sql_parts = []
        params = []
        
        full_name = f"{first_name} {last_name}".strip()
        if full_name:
            sql_parts.append("full_name=%s")
            params.append(full_name)
        if email:
            sql_parts.append("email=%s")
            params.append(email)
        if location:
            sql_parts.append("location=%s")
            params.append(location)
        if profile_path:
            sql_parts.append("profile_photo=%s")
            params.append(profile_path)
        if banner_path:
            sql_parts.append("banner_image=%s")
            params.append(banner_path)

        if not sql_parts:
            return jsonify({"message": "Tidak ada data untuk diperbarui"}), 400

        params.append(user_id)
        sql = f"UPDATE users SET {', '.join(sql_parts)} WHERE id=%s"
        
        with conn.cursor() as cursor:
            cursor.execute(sql, tuple(params))
            conn.commit()

        # Ambil ulang data user terbaru untuk dikirimkan kembali ke frontend
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username, email, full_name, profile_photo, banner_image, location FROM users WHERE id = %s", (user_id,))
            updated_user = cursor.fetchone()
            if updated_user:
                # [FIX] Pastikan data yang dikembalikan juga menggunakan URL absolut
                updated_user['profile_photo'] = make_url_absolute(updated_user.get('profile_photo'))
                updated_user['banner_image'] = make_url_absolute(updated_user.get('banner_image'))

        return jsonify({"message": "Profil berhasil diperbarui", "user": updated_user}), 200

    except mysql.connector.Error as err:
        # [DEBUG] Mencetak error spesifik dari database ke terminal Flask
        print(f"Error saat update profil: {err}")
        # Memberikan pesan error yang lebih informatif
        if err.errno == 1062: # Error untuk duplicate entry
            return jsonify({"message": "Email yang Anda masukkan sudah digunakan."}), 409
        return jsonify({"message": f"Terjadi kesalahan pada database: {err.msg}"}), 500
    except Exception as e:
        print(f"Error umum saat update profil: {e}")
        return jsonify({"message": "Terjadi kesalahan internal pada server."}), 500
    finally:
        if conn:
            conn.close()


        # Endpoint admin verifikasi user
#@app.route('/api/admins/verify-user/<int:user_id>', methods=['POST'])
#@token_required(role="admin")
#def admin_verify_user(current_admin, user_id):
   # conn = get_db_connection()
    #if not conn:
     #   return jsonify({"message": "Database connection failed"}), 500
    #try:
     #   with conn.cursor() as cursor:
      #      cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
       #       return jsonify({"message": "User not found"}), 404
         #   cursor.execute("UPDATE users SET is_verified = TRUE WHERE id = %s", (user_id,))
        #    conn.commit()
       # return jsonify({"message": "User berhasil diverifikasi"}), 200
    #except mysql.connector.Error as err:
     #   print(f"Database query error: {err}")
      #  return jsonify({"message": "Database query failed"}), 500
    #finally:
     #   conn.close()
## ===========================
# ADMIN ROUTES
# ===========================


@app.route('/api/campaigns/<int:blockchain_campaign_id>', methods=['GET'])
def get_campaign_detail_by_blockchain_id(blockchain_campaign_id):
    """
    Mengambil detail kampanye berdasarkan blockchain_campaign_id,
    sekaligus memeriksa dan memperbarui status jika sudah kedaluwarsa.
    """
    print(f"\n===== SERVER MENJALANKAN FUNGSI get_campaign_detail_by_blockchain_id UNTUK BLOCKCHAIN_ID: {blockchain_campaign_id} =====\n")
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Koneksi database gagal"}), 500

    try:
        with conn.cursor(dictionary=True) as cursor:
            # 1. Cari campaign berdasarkan blockchain_campaign_id
            cursor.execute("""
                SELECT c.*, a.username AS owner_name 
                FROM campaigns c 
                JOIN admins a ON c.admin_id = a.id 
                WHERE c.blockchain_campaign_id = %s
            """, (blockchain_campaign_id,))
            campaign = cursor.fetchone()

        if not campaign:
            return jsonify({"message": "Kampanye dengan blockchain ID tersebut tidak ditemukan"}), 404

        # 2. Ambil data dari IPFS (opsional, jika diperlukan)
        ipfs_data = fetch_from_ipfs(campaign.get('ipfs_cid'))
        if ipfs_data:
            campaign.update(ipfs_data)

        # 3. Logika pengecekan tanggal kedaluwarsa
        deadline_obj = campaign.get('deadline')
        is_expired = False
        
        if isinstance(deadline_obj, date):
            is_expired = date.today() > deadline_obj
            campaign['deadline'] = deadline_obj.isoformat()
        
        campaign['is_expired'] = is_expired

        # 4. Logika pembaruan status otomatis jika kedaluwarsa
        campaign_primary_id = campaign.get('id') # Ambil ID utama untuk query UPDATE
        
        if campaign['is_expired'] and campaign.get('status') == 'active':
            update_conn = get_db_connection()
            with update_conn.cursor() as update_cursor:
                # Gunakan ID utama untuk memperbarui baris yang benar
                update_cursor.execute("UPDATE campaigns SET status='inactive' WHERE id=%s", (campaign_primary_id,))
                update_conn.commit()
            update_conn.close()
            
            campaign['status'] = 'inactive' # Perbarui status di respons
            print(f"--- DATABASE BERHASIL DI-UPDATE UNTUK ID {campaign_primary_id} (Blockchain ID: {blockchain_campaign_id}) ---")

        # 5. Kirim respons
        return jsonify(campaign), 200

    except Exception as e:
        print(f"Error di server: {e}")
        return jsonify({"message": "Error internal server"}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()



@app.route('/api/admins/register', methods=['POST'])
def admin_register():
    # Ambil data dari form
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    profile_photo = request.files.get('profile_photo')  # ambil file

    if not all([username, email, password]):
        return jsonify({"message": "Missing required fields"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"message": "Email already registered"}), 409
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Simpan foto profil jika ada
            photo_filename = None
            if profile_photo and allowed_file(profile_photo.filename):
                os.makedirs(app.config['UPLOAD_ADMIN_PROFILE_FOLDER'], exist_ok=True)
                filename = f"admin_{username}_{secure_filename(profile_photo.filename)}"
                save_path = os.path.join(app.config['UPLOAD_ADMIN_PROFILE_FOLDER'], filename)
                profile_photo.save(save_path)
                photo_filename = filename

            # Insert dengan kolom profile_photo
            cursor.execute(
                "INSERT INTO admins (username, email, password, profile_photo) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_pw, photo_filename)
            )
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

# Endpoint untuk mendapatkan semua user (admin)
@app.route('/api/admins/users', methods=['GET'])
@token_required(role="admin")
def get_all_users(current_admin):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username, nim, email, is_verified FROM users ORDER BY id DESC")
            users = cursor.fetchall()
        return jsonify(users)
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

# ===========================
# CAMPAIGN ROUTES (ADMIN ONLY CREATE)
# ===========================
# Endpoint: Create Campaign (Admin)
@app.route('/api/admins/campaigns', methods=['POST'])
@token_required(role="admin")
def create_campaign(current_admin):
    admin_id = current_admin['admin_id']

    # Mengambil data dari form
    title = request.form.get('title')
    story = request.form.get('story')
    goal_amount = request.form.get('goal_amount')
    deadline = request.form.get('deadline')
    category = request.form.get('category')
    blockchain_campaign_id = request.form.get('blockchain_campaign_id')

    # Validasi input data wajib
    if not title or not story or not goal_amount or not deadline or blockchain_campaign_id is None:
        return jsonify({"message": "Missing required fields"}), 400

    # Mengambil gambar dari form jika ada
    image_file = request.files.get('image')
    image_url = None

    # Simpan gambar ke folder lokal jika ada gambar
    if image_file and allowed_file(image_file.filename):
        # Tentukan folder penyimpanan
        os.makedirs(app.config['UPLOAD_CAMPAIGN_FOLDER'], exist_ok=True)
        filename = secure_filename(image_file.filename)
        save_path = os.path.join(app.config['UPLOAD_CAMPAIGN_FOLDER'], filename)
        image_file.save(save_path)
        image_url = f"/{app.config['UPLOAD_CAMPAIGN_FOLDER']}/{filename}"  # Path lokal gambar
    else:
        return jsonify({"message": "Image file missing or not allowed"}), 400

    # Membuat JSON Payload untuk Pinata (data kampanye tanpa gambar)
    pinata_payload = {
        "title": title,
        "description": story,
        "goal_amount": goal_amount
    }

    # Upload JSON ke Pinata
    pinata_res = upload_json_to_pinata(pinata_payload)
    if 'IpfsHash' not in pinata_res:
        return jsonify({"message": "Failed to upload campaign data to IPFS", "error": pinata_res}), 500
    ipfs_cid = pinata_res['IpfsHash']

    # Simpan data campaign di MySQL
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:

            sql_query = """
                INSERT INTO campaigns 
                (admin_id, ipfs_cid, deadline, image_url, category, status, blockchain_campaign_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            # Tuple sekarang berisi 7 nilai, termasuk 'pending' agar cocok dengan query
            values = (admin_id, ipfs_cid, deadline, image_url, category, 'pending', blockchain_campaign_id)
            
            cursor.execute(sql_query, values)
            conn.commit()
            

        return jsonify({"message": "Campaign created successfully, menunggu verifikasi"}), 201
    except Exception as e:
        # Mencetak error spesifik ke terminal Flask untuk debugging
        print(f"Error creating campaign: {e}") 
        return jsonify({"message": "Failed to create campaign"}), 500
    finally:
        conn.close()

@app.route('/api/admins/campaigns', methods=['GET'])
@token_required(role="admin")
def get_admin_campaigns(current_admin):
    admin_id = current_admin['admin_id']
    conn = get_db_connection()
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT 
                    c.*, 
                    a.username AS owner_name 
                FROM campaigns c
                JOIN admins a ON c.admin_id = a.id
                WHERE c.admin_id = %s
                ORDER BY c.id DESC
            """, (admin_id,))
            campaigns = cursor.fetchall()

            # Fetch IPFS data for each campaign
            for campaign in campaigns:
                print("==== [DEBUG] RAW CAMPAIGN ====")
                print(campaign)
                if campaign['ipfs_cid']:  # If IPFS CID exists
                        
                    ipfs_data = fetch_from_ipfs(campaign['ipfs_cid'])
                    print("[IPFS] Data from IPFS:", ipfs_data)
                    if ipfs_data:
                        # Merge IPFS data with the campaign data
                        campaign['title'] = ipfs_data.get('title', '')
                        campaign['story'] = ipfs_data.get('description', '')
                        campaign['goal_amount'] = ipfs_data.get('goal_amount', campaign['goal_amount'])
                        print("[AFTER MERGE] Campaign:", campaign)


            # Ensure the image_url is complete (with http://localhost:5000 prefix)
            campaigns = [ensure_full_image_url(campaign) for campaign in campaigns]

            return jsonify(campaigns), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"message": "Internal server error"}), 500
    finally:
        conn.close()



@app.route('/api/campaigns', methods=['GET'])
def get_campaigns():
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM campaigns WHERE status = 'active'")
            campaigns = cursor.fetchall()

            # Fetch IPFS data for each campaign
            for campaign in campaigns:
                print("==== [DEBUG] RAW CAMPAIGN ====")
                print(campaign)
                if campaign['ipfs_cid']:  # If IPFS CID exists
                    print(f"[IPFS] CID: {campaign['ipfs_cid']}")
                    ipfs_data = fetch_from_ipfs(campaign['ipfs_cid'])
                    print("[IPFS] Data from IPFS:", ipfs_data)
                    if ipfs_data:
                        # Merge IPFS data with the campaign data
                        campaign['title'] = ipfs_data.get('title', '')
                        campaign['story'] = ipfs_data.get('description', '')
                        campaign['goal_amount'] = ipfs_data.get('goal_amount', campaign['goal_amount'])
                       
                        print("[AFTER MERGE] Campaign:", campaign)


            # Ensure the image_url is complete (with http://localhost:5000 prefix)
            campaigns = [ensure_full_image_url(campaign) for campaign in campaigns]
            return jsonify(campaigns), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"message": "Internal server error"}), 500
    finally:
        conn.close()


# Campaign list untuk user (hanya yang active)
@app.route('/api/campaigns', methods=['GET'])
def get_active_campaigns():
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM campaigns WHERE status = 'active'")
            campaigns = cursor.fetchall()
        return jsonify(campaigns), 200
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()


# ===========================
# DONATION ROUTES
# ===========================

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
            cursor.execute("INSERT INTO donations (user_id, campaign_id, amount, message) VALUES (%s, %s, %s, %s)",
                           (user_id, data['campaign_id'], data['amount'], data.get('message')))
            conn.commit()
        return jsonify({"message": "Donation successful"}), 201
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()

# ===========================
# ADMIN CAMPAIGN MANAGEMENT
# ===========================

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


@app.route('/api/admins/campaigns/<int:campaign_id>', methods=['DELETE'])
@token_required(role="admin")
def delete_campaign(current_admin, campaign_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    
    try:
        with conn.cursor() as cursor:
            # Periksa apakah campaign ada
            cursor.execute("SELECT id FROM campaigns WHERE id = %s", (campaign_id,))
            if not cursor.fetchone():
                return jsonify({"message": "Campaign not found"}), 404

            # Hapus data donasi terlebih dahulu untuk menjaga integritas
            cursor.execute("DELETE FROM donations WHERE campaign_id = %s", (campaign_id,))

            # Hapus campaign-nya
            cursor.execute("DELETE FROM campaigns WHERE id = %s", (campaign_id,))
            conn.commit()

        return jsonify({"message": "Campaign deleted successfully"}), 200

    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500

    finally:
        conn.close()

@app.route('/api/admins/campaigns/<int:campaign_id>', methods=['GET'])
@token_required(role="admin")
def get_admin_campaign_detail(current_admin, campaign_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT 
                    c.*, 
                    a.username AS owner_name,
                    a.email AS owner_email,
                    a.profile_photo AS profile_photo,
                    c.image_url
                FROM campaigns c
                JOIN admins a ON c.admin_id = a.id
                WHERE c.id = %s
            """, (campaign_id,))
            campaign = cursor.fetchone()

            if campaign:
                # Mengupdate image_url agar bisa diakses dari server lokal
                if campaign['image_url']:
                    # Pastikan image_url diawali dengan http://localhost:5000 jika belum
                    if not campaign['image_url'].startswith("http"):
                        campaign['image_url'] = f"http://localhost:5000{campaign['image_url']}"

                return jsonify(campaign), 200
            else:
                return jsonify({"message": "Campaign not found"}), 404
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()



# ===========================
# OTP Routes (Kirim & Verifikasi)
# ===========================

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')
    otp = str(random.randint(100000, 999999))

    if not email:
        return jsonify({"message": "Email is required"}), 400

    # Validasi email kampus di sini juga (optional)
    if not is_valid_campus_email(email):
        return jsonify({"message": "Email harus email kampus domain umy.ac.id"}), 400

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

        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP code is: {otp}'
        mail.send(msg)

        return jsonify({"message": "OTP sent successfully"}), 200

    except Exception as e:
        print(f"Error sending OTP: {e}")
        return jsonify({"message": "Failed to send OTP"}), 500

    finally:
        conn.close()

@app.route('/api/users/verify-otp', methods=['POST'])
def verify_otp_and_register():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"message": "Email and OTP are required"}), 400

    # Verifikasi OTP
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT otp FROM otp_codes WHERE email=%s", (email,))
            result = cursor.fetchone()

            if result and result[0] == otp:
                # OTP valid, proceed with saving user data
                username = data.get('username')
                nim = data.get('nim')
                password = data.get('password')

                if not all([username, nim, password]):
                    return jsonify({"message": "Missing required fields (username, nim, password)"}), 400

                # Validasi email kampus (sekali lagi)
                if not is_valid_campus_email(email):
                    return jsonify({"message": "Email must be from the domain umy.ac.id"}), 400

                # Cek jika email atau NIM sudah terdaftar
                cursor.execute("SELECT * FROM users WHERE email = %s OR nim = %s", (email, nim))
                if cursor.fetchone():
                    return jsonify({"message": "Email or NIM already registered"}), 409

                # Hash password
                hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                # Simpan pengguna ke dalam database
                cursor.execute("INSERT INTO users (username, nim, email, password, is_verified) VALUES (%s, %s, %s, %s, %s)",
                               (username, nim, email, hashed_pw, True))  # Mark as verified
                conn.commit()

                # Hapus OTP setelah berhasil verifikasi
                cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
                conn.commit()

                return jsonify({"message": "User registered successfully"}), 201

            else:
                return jsonify({"message": "Invalid OTP"}), 400

    except Exception as e:
        print(f"Error verifying OTP and registering user: {e}")
        return jsonify({"message": "Failed to verify OTP and register user"}), 500
    finally:
        conn.close()

@app.route('/api/users/reset-verify-otp', methods=['POST'])
def verify_otp_reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"message": "Email and OTP are required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500

    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT otp FROM otp_codes WHERE email=%s", (email,))
            result = cursor.fetchone()

            if result and result[0] == otp:
                # OTP valid, cukup return OK, nanti password diubah di endpoint lain
                return jsonify({"message": "OTP valid"}), 200
            else:
                return jsonify({"message": "Invalid OTP"}), 400
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return jsonify({"message": "Failed to verify OTP"}), 500
    finally:
        conn.close()


@app.route('/api/users/register-final', methods=['POST'])
def final_register():
    data = request.json
    username = data['username']
    nim = data['nim']
    email = data['email']
    password = data['password']

    # Lakukan penyimpanan data pengguna ke database
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO users (username, nim, email, password, is_verified) VALUES (%s, %s, %s, %s, %s)",
                           (username, nim, email, bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()), True))  # Mark as verified
            conn.commit()
        return jsonify({"message": "User successfully registered"}), 201
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return jsonify({"message": "Database query failed"}), 500
    finally:
        conn.close()




# Mengambil data kampanye dari database dan menggabungkannya dengan IPFS
# Campaign route to get campaign details
@app.route('/api/campaigns/<int:campaign_id>', methods=['GET'])
def get_campaign_detail(campaign_id):
    # LOKASI PRINT YANG BENAR ADALAH DI SINI, DI LUAR LOGIKA APAPUN
    print(f"\n===== SERVER MENERIMA REQUEST UNTUK ID: {campaign_id} =====\n")
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Koneksi database gagal"}), 500

    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT c.*, a.username AS owner_name FROM campaigns c
                JOIN admins a ON c.admin_id = a.id
                WHERE c.id = %s
            """, (campaign_id,))
            campaign = cursor.fetchone()

            if not campaign:
                return jsonify({"message": "Kampanye tidak ditemukan"}), 404

            ipfs_data = fetch_from_ipfs(campaign.get('ipfs_cid'))
            if ipfs_data:
                campaign.update(ipfs_data)

            # --- [LOGIKA FINAL UNTUK TANGGAL] ---
            deadline_obj = campaign.get('deadline')
            is_expired = False
            
            if isinstance(deadline_obj, date):
                is_expired = date.today() > deadline_obj
                campaign['deadline'] = deadline_obj.isoformat()
            
            campaign['is_expired'] = is_expired

            # --- Logika Otomatisasi Status ---
            if campaign['is_expired'] and campaign.get('status') == 'active':
                update_conn = get_db_connection()
                with update_conn.cursor() as update_cursor:
                    update_cursor.execute("UPDATE campaigns SET status='inactive' WHERE id=%s", (campaign_id,))
                    update_conn.commit()
                update_conn.close()
                campaign['status'] = 'inactive'
                print(f"--- STATUS UNTUK ID {campaign_id} BERHASIL DIUBAH KE INACTIVE ---")

            return jsonify(campaign), 200

    except Exception as e:
        print(f"Terjadi error pada server: {e}")
        return jsonify({"message": f"Terjadi kesalahan internal: {e}"}), 500
    finally:
        if conn and conn.is_connected():
            conn.close()
            
            


@app.route('/api/admins/users/<int:user_id>', methods=['GET'])
@token_required(role="admin")
def get_user_detail(current_admin, user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Database connection failed"}), 500
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT id, username, nim, email, full_name, profile_photo, banner_image, location, is_verified
                FROM users
                WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()
            if user:
                return jsonify(user), 200
            else:
                return jsonify({"message": "User not found"}), 404
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



import os
from flask import request, jsonify

UPLOAD_ADMIN_PROFILE_FOLDER = 'uploads/profiles/admins'
app.config['UPLOAD_ADMIN_PROFILE_FOLDER'] = UPLOAD_ADMIN_PROFILE_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/admins/profile/upload', methods=['POST'])
@token_required(role="admin")
def upload_admin_profile(current_admin):
    print("----DEBUG----")
    print("FILES:", request.files)
    print("FORM:", request.form)
    print("HEADERS:", request.headers)
    admin_id = current_admin['admin_id']
    file = request.files.get('profile_photo')
    print("Selected file:", file)
    if not file or not allowed_file(file.filename):
        print("ALASAN GAGAL: ", "File tidak ditemukan" if not file else "Invalid file type")
        return jsonify({"message": "No file or invalid file type"}), 400

    filename = f"admin_{admin_id}_{secure_filename(file.filename)}"
    save_path = os.path.join(app.config['UPLOAD_ADMIN_PROFILE_FOLDER'], filename)
    os.makedirs(app.config['UPLOAD_ADMIN_PROFILE_FOLDER'], exist_ok=True)
    file.save(save_path)

    # Simpan nama file ke database
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE admins SET profile_photo = %s WHERE id = %s", (filename, admin_id))
            conn.commit()
        return jsonify({"message": "Profile photo updated", "filename": filename}), 200
    finally:
        conn.close()

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({"message": "Email, OTP, dan password baru wajib diisi"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"message": "Koneksi database gagal"}), 500

    try:
        with conn.cursor() as cursor:
            # Cek OTP sesuai email
            cursor.execute("SELECT otp FROM otp_codes WHERE email=%s", (email,))
            result = cursor.fetchone()
            if not result or result[0] != otp:
                return jsonify({"message": "OTP salah"}), 400

            # Hash password baru
            hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Update password user
            cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_pw, email))
            conn.commit()

            # (Optional) Hapus OTP biar nggak bisa dipake lagi
            cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))
            conn.commit()

        return jsonify({"message": "Password berhasil direset"}), 200

    except Exception as e:
        print(f"Error saat reset password: {e}")
        return jsonify({"message": "Gagal reset password"}), 500

    finally:
        conn.close()







if __name__ == "__main__":
    app.run(debug=True)
