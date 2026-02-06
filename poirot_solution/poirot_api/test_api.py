import requests
import json

# Hedef adres (Senin API)
url = 'http://127.0.0.1:5000/api/scan'

# Gönderilecek veri
data = {'target': 'scanme.nmap.org'}

print("🕵️‍♂️ Ajan gönderiliyor...")

try:
    # İsteği at
    response = requests.post(url, json=data)
    
    # Cevabı yazdır
    print(f"📡 Durum Kodu: {response.status_code}")
    print("📄 Gelen Cevap:")
    
    # JSON'ı güzelce yazdır
    print(json.dumps(response.json(), indent=4))

except Exception as e:
    print(f"🔥 Hata: {e}")