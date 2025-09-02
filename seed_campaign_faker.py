import requests
from faker import Faker
import random
from datetime import datetime, timedelta

# GANTI sesuai konfigurasi kamu
BASE_URL = "http://localhost:5000"
ADMIN_EMAIL = "admin@gmail.com"   # GANTI ke email admin kamu
ADMIN_PASSWORD = "Password123"       # GANTI ke password admin kamu
IMAGE_PATH = "C:\\Tugas akhir\\backend-donasi\\dummy.jpeg"          # Gambar lokal .jpg/.png

fake = Faker()

# Login admin → ambil token JWT
def login_admin():
    response = requests.post(f"{BASE_URL}/api/admins/login", json={
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    })
    if response.status_code == 200:
        token = response.json()["token"]
        print("[✓] Login berhasil")
        return token
    else:
        print("[X] Gagal login:", response.json())
        exit()

# Generate data dummy
def generate_campaign_data():
    return {
        "title": fake.sentence(nb_words=4),
        "story": fake.paragraph(nb_sentences=5),
        "goal_amount": round(random.uniform(0.1, 5.0), 2),
        "deadline": (datetime.now() + timedelta(days=random.randint(7, 30))).date().isoformat(),
        "category": random.choice(["Health", "Education", "Emergency"]),
        "blockchain_campaign_id": random.randint(100, 999)  # ID dummy
    }

# Kirim data campaign ke backend
def post_campaign(token, data):
    headers = {"Authorization": f"Bearer {token}"}
    with open(IMAGE_PATH, "rb") as img_file:
        files = {"image": img_file}
        response = requests.post(f"{BASE_URL}/api/admins/campaigns",
                                 headers=headers,
                                 data=data,
                                 files=files)
    return response

# MAIN
if __name__ == "__main__":
    token = login_admin()
    for i in range(5):
        data = generate_campaign_data()
        print(f"[{i+1}] Menambahkan campaign: {data['title']}")
        response = post_campaign(token, data)
        if response.status_code == 201:
            print("   → [✓] Campaign berhasil ditambahkan.")
        else:
            print("   → [X] Gagal:", response.json())
