from flask import Blueprint, render_template, request, jsonify
from app import db
from app.models.scan_record import ScanRecord
from app.core.scanner import NmapScanner

main = Blueprint('main', __name__)

# Anasayfayı açan rota
@main.route('/')
def home():
    return render_template('pages/home.html')

# Taramayı başlatan API rotası (Frontend buraya istek atacak)
@main.route('/api/scan', methods=['POST'])
def start_scan():
    # 1. Frontend'den gelen veriyi al
    data = request.get_json()
    target_ip = data.get('target')
    
    if not target_ip:
        return jsonify({"error": "IP adresi girilmedi mon ami!"}), 400

    # 2. Tarama Motorunu Çalıştır
    scanner = NmapScanner()
    result = scanner.scan_target(target_ip)

    # 3. Sonucu Veritabanına Kaydet (Hafıza)
    if result.get('success'):
        # Başarılıysa verileri doldur
        new_record = ScanRecord(
            target_ip=target_ip,
            status='completed',
            raw_data=result['full_data'] # Tüm Nmap çıktısını saklıyoruz
        )
    else:
        # Hata varsa, hatayı kaydet
        new_record = ScanRecord(
            target_ip=target_ip,
            status='failed',
            raw_data={"error": result.get('error')}
        )

    # DB'ye işle (Commit)
    try:
        db.session.add(new_record)
        db.session.commit()
        print("Sonuç veritabanına kaydedildi.")
    except Exception as e:
        print(f"Veritabanı Hatası: {e}")
        db.session.rollback() # Hata olursa işlemi geri al

    # 4. Sonucu Frontend'e Döndür
    return jsonify(result)