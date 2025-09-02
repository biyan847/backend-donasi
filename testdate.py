import requests

# Targetkan ID 13 yang sudah kita siapkan di database
TARGET_CAMPAIGN_ID = 19
SERVER_URL = f"http://localhost:5000/api/campaigns/{TARGET_CAMPAIGN_ID}"

def run_test():
    """Fungsi utama untuk menjalankan pengujian."""
    print("="*50)
    print(f"🚀 MEMULAI PENGUJIAN OTOMATISASI STATUS KAMPANYE 🚀")
    print(f"   Menargetkan Kampanye ID: {TARGET_CAMPAIGN_ID}")
    print("="*50)
    try:
        response = requests.get(SERVER_URL)
        print(f"-> Status Respons Diterima: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            status = data.get('status')
            is_expired = data.get('is_expired')

            print("\n[HASIL DARI SERVER]")
            print(f"   - Deadline  : {data.get('deadline')}")
            print(f"   - Status    : {status}")
            print(f"   - Expired?  : {is_expired}")

            print("\n[VERIFIKASI]")
            if status == 'inactive' and is_expired is True:
                print("   ✅ PENGUJIAN BERHASIL! Status otomatis berubah menjadi 'inactive'.")
            else:
                print("   ❌ PENGUJIAN GAGAL. Status tidak berubah seperti yang diharapkan.")
        else:
            print(f"   DETAIL ERROR: {response.text}")

    except requests.exceptions.ConnectionError:
        print("\n❌ KESALAHAN: Gagal terhubung ke server. Pastikan app.py berjalan.")
    except Exception as e:
        print(f"\n❌ Terjadi error yang tidak terduga: {e}")
    print("="*50)

if __name__ == "__main__":
    run_test()