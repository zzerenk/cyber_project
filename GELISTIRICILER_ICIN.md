# 🕵️‍♂️ Poirot Network Scanner - Geliştiriciler İçin Dokümantasyon

## 📋 İçindekiler
1. [Proje Hakkında](#proje-hakkında)
2. [Mimari Yapı](#mimari-yapı)
3. [Klasör ve Dosya Yapısı](#klasör-ve-dosya-yapısı)
4. [Bileşenlerin Detaylı Açıklaması](#bileşenlerin-detaylı-açıklaması)
5. [Kurulum ve Çalıştırma](#kurulum-ve-çalıştırma)
6. [Geliştirme Ortamı Hazırlığı](#geliştirme-ortamı-hazırlığı)
7. [Nasıl Çalışır?](#nasıl-çalışır)
8. [Geliştirme Notları](#geliştirme-notları)

---

## 🎯 Proje Hakkında

**Poirot Network Scanner**, ağ güvenliği ve penetrasyon testi için geliştirilmiş bir web tabanlı Nmap tarama aracıdır. Hercule Poirot dedektifinden esinlenilerek adlandırılmış bu proje, kullanıcıların hedef IP adreslerini veya domain'leri tarayarak açık portları, çalışan servisleri ve güvenlik açıklarını tespit etmelerini sağlar.

### Temel Özellikler:
- 🔍 **Nmap Entegrasyonu**: Python-nmap kütüphanesi kullanarak güçlü port taraması
- 🌐 **Web Arayüzü**: Flask backend ve modern HTML/CSS/JS frontend
- 💾 **Veritabanı Entegrasyonu**: PostgreSQL ile tarama sonuçlarını kaydetme
- 🎨 **Kullanıcı Dostu Tasarım**: Bootstrap tabanlı responsive arayüz
- 📊 **Geçmiş Kayıtlar**: Tüm tarama sonuçları veritabanında saklanır

### Kullanım Alanları:
- Siber güvenlik eğitimleri
- Penetrasyon testi eğitimleri
- Ağ güvenlik analizleri
- Sistem yöneticisi araçları

---

## 🏗️ Mimari Yapı

Proje, **katmanlı mimari (layered architecture)** prensibine göre tasarlanmıştır:

```mermaid
graph TB
    subgraph "Frontend Layer - Presentation"
        A[Web Browser/UI]
        B[HTML Templates]
        C[JavaScript - main.js]
    end
    
    subgraph "Backend Layer - Application"
        D[Flask Application]
        E[API Routes]
        F[Business Logic]
    end
    
    subgraph "Core Layer - Domain"
        G[Nmap Scanner Module]
        H[Scan Logic]
    end
    
    subgraph "Data Layer - Persistence"
        I[SQLAlchemy ORM]
        J[ScanRecord Model]
        K[(PostgreSQL Database)]
    end
    
    A --> B
    B --> C
    C --> E
    E --> F
    F --> G
    G --> H
    F --> I
    I --> J
    J --> K
    
    style A fill:#e1f5ff
    style D fill:#fff4e1
    style G fill:#ffe1e1
    style K fill:#e1ffe1
```

### Teknoloji Stack:

| Katman | Teknoloji | Amaç |
|--------|-----------|------|
| **Frontend** | HTML5, CSS3, Bootstrap 5, JavaScript | Kullanıcı arayüzü |
| **Backend** | Python 3.x, Flask | Web framework ve API |
| **Scanner** | python-nmap, Nmap | Port tarama motoru |
| **Database** | PostgreSQL, SQLAlchemy | Veri saklama |
| **Config** | python-dotenv | Ortam değişkenleri |

---

## 📁 Klasör ve Dosya Yapısı

```
cyber_project/
│
├── .git/                          # Git version control
├── .gitignore                     # Git ignore kuralları
├── README.md                      # Proje açıklaması (boş)
├── GELISTIRICILER_ICIN.md        # Bu dosya!
│
├── db/                            # Veritabanı şemaları ve scriptler
│   ├── schema/                    # Tablo şemaları
│   ├── queries/                   # Hazır SQL sorguları
│   ├── scripts/                   # Yardımcı scriptler
│   └── seeds/                     # Test verileri
│
└── poirot_solution/               # Ana uygulama klasörü
    │
    ├── poirot_api/                # Backend API (Flask)
    │   │
    │   ├── .env                   # Ortam değişkenleri (GİZLİ!)
    │   ├── config.py              # Uygulama konfigürasyonu
    │   ├── run.py                 # Uygulama başlatıcı
    │   ├── test_api.py            # API test dosyası
    │   ├── requirements.txt       # Python bağımlılıkları
    │   ├── venv/                  # Python virtual environment
    │   │
    │   └── app/                   # Ana uygulama paketi
    │       │
    │       ├── __init__.py        # Flask app factory
    │       │
    │       ├── api/               # API Endpoints
    │       │   └── routes.py      # HTTP rotaları
    │       │
    │       ├── core/              # İş mantığı (business logic)
    │       │   └── scanner.py     # Nmap tarama motoru
    │       │
    │       └── models/            # Veritabanı modelleri
    │           └── scan_record.py # Tarama kayıtları modeli
    │
    └── poirot_web/                # Frontend (Templates & Static)
        │
        ├── static/                # Statik dosyalar
        │   └── js/
        │       └── main.js        # Frontend JavaScript
        │
        └── templates/             # HTML şablonları
            ├── layouts/
            │   └── base.html      # Ana layout
            └── pages/
                └── home.html      # Anasayfa
```

---

## 🔧 Bileşenlerin Detaylı Açıklaması

### 1️⃣ Backend API (`poirot_api/`)

#### 📄 [`run.py`](file:///c:/cyber_project/poirot_solution/poirot_api/run.py)
**Amaç**: Uygulamanın giriş noktası (entry point)

```python
from app import create_app

app = create_app()

if __name__ == '__main__':
    # host='0.0.0.0' dışarıdan erişim (Kali -> Windows) için şart!
    app.run(host='0.0.0.0', port=5000, debug=True)
```

**Özellikleri**:
- Flask uygulamasını başlatır
- `0.0.0.0` kullanarak tüm network interface'lerinden erişime izin verir
- Port 5000'de çalışır
- Debug modu aktif (geliştirme için)

---

#### 📄 [`config.py`](file:///c:/cyber_project/poirot_solution/poirot_api/config.py)
**Amaç**: Uygulama konfigürasyonu

**Özellikler**:
- `.env` dosyasından ortam değişkenlerini yükler
- `SECRET_KEY`: Flask session güvenliği için
- `DATABASE_URL`: PostgreSQL bağlantı stringi
- `SQLALCHEMY_TRACK_MODIFICATIONS`: False (performans için)

---

#### 📄 [`.env`](file:///c:/cyber_project/poirot_solution/poirot_api/.env)
**Amaç**: Gizli bilgilerin saklanması

> [!CAUTION]
> Bu dosya GİT'e eklenmemelidir! `.gitignore` içinde zaten var.

```env
SECRET_KEY=rastgele-gizli-anahtar-buraya
DATABASE_URL=postgresql://postgres:POSTGRESQL_SIFRENIZ@localhost/poirot_db
FLASK_APP=run.py
FLASK_DEBUG=1
```

**Değişkenler**:
- `SECRET_KEY`: Flask session encryption (kendi rastgele anahtarınızı yazın)
- `DATABASE_URL`: PostgreSQL bağlantı bilgileri
  - Format: `postgresql://kullanici:sifre@host/veritabani_adi`
  - `POSTGRESQL_SIFRENIZ`: PostgreSQL kurulumunda **sizin belirlediğiniz** şifre
- `FLASK_APP`: Flask'ın hangi dosyayı çalıştıracağı
- `FLASK_DEBUG`: Debug modu (1=aktif, 0=pasif)

> [!IMPORTANT]
> Bu dosyayı kendiniz oluşturmalısınız! Repo'da varsayılan olarak bulunmaz (güvenlik için).

---

#### 📄 [`requirements.txt`](file:///c:/cyber_project/poirot_solution/poirot_api/requirements.txt)
**Amaç**: Python bağımlılıklarının listesi

```
flask                  # Web framework
python-dotenv          # .env dosyası okuma
python-nmap            # Nmap entegrasyonu
psycopg2-binary        # PostgreSQL driver
flask-sqlalchemy       # ORM (Object-Relational Mapping)
```

---

### 2️⃣ App Package (`app/`)

#### 📄 [`app/__init__.py`](file:///c:/cyber_project/poirot_solution/poirot_api/app/__init__.py)
**Amaç**: Flask Application Factory Pattern

**Kritik İşlevler**:

1. **Database Initialization**:
```python
db = SQLAlchemy()  # Global db nesnesi
```

2. **Template/Static Folder Configuration**:
```python
# poirot_web klasöründeki template'leri kullan
web_folder = os.path.join(root_dir, 'poirot_web')
template_folder = os.path.join(web_folder, 'templates')
static_folder = os.path.join(web_folder, 'static')
```

3. **Database Table Creation**:
```python
with app.app_context():
    db.create_all()  # Tabloları oluştur
    # Kontrol ve debug mesajları
```

4. **Blueprint Registration**:
```python
from app.api.routes import main
app.register_blueprint(main)
```

**Neden Application Factory?**
- Test edilebilirlik
- Birden fazla uygulama instance'ı oluşturabilme
- Temiz dependency injection

---

### 3️⃣ API Routes (`app/api/routes.py`)

#### 📄 [`routes.py`](file:///c:/cyber_project/poirot_solution/poirot_api/app/api/routes.py)
**Amaç**: HTTP endpoint'lerinin tanımlanması

**Endpoint'ler**:

##### 🏠 `GET /`
```python
@main.route('/')
def home():
    return render_template('pages/home.html')
```
- Anasayfayı gösterir
- Template: `poirot_web/templates/pages/home.html`

##### 🔍 `POST /api/scan`
```python
@main.route('/api/scan', methods=['POST'])
def start_scan():
    # 1. Frontend'den veriyi al
    data = request.get_json()
    target_ip = data.get('target')
    
    # 2. Taramayı yap
    scanner = NmapScanner()
    result = scanner.scan_target(target_ip)
    
    # 3. Veritabanına kaydet
    new_record = ScanRecord(
        target_ip=target_ip,
        status='completed',
        raw_data=result['full_data']
    )
    db.session.add(new_record)
    db.session.commit()
    
    # 4. Sonucu döndür
    return jsonify(result)
```

**İş Akışı**:
1. JSON request body'sinden `target` parametresini al
2. `NmapScanner` ile taramayı başlat
3. Sonuçları `ScanRecord` modeline kaydet
4. PostgreSQL'e commit et
5. JSON response dön

---

### 4️⃣ Core Business Logic (`app/core/scanner.py`)

#### 📄 [`scanner.py`](file:///c:/cyber_project/poirot_solution/poirot_api/app/core/scanner.py)
**Amaç**: Nmap tarama işlemlerinin gerçekleştirilmesi

**Class: `NmapScanner`**

##### Constructor (`__init__`)
```python
def __init__(self):
    # Nmap yollarını PATH'e ekle
    nmap_yolu_1 = r"C:\Program Files (x86)\Nmap"
    nmap_yolu_2 = r"C:\Program Files\Nmap"
    os.environ['PATH'] += ";" + nmap_yolu_1 + ";" + nmap_yolu_2
    
    self.nm = nmap.PortScanner()
```

**Neden PATH'e ekleniyor?**
- Windows'ta Nmap'in bulunabilmesi için
- python-nmap kütüphanesi `nmap` komutunu PATH'te arar

##### Method: `scan_target(target_ip, scan_type='quick')`
```python
def scan_target(self, target_ip, scan_type='quick'):
    arguments = '-Pn -sV --version-light'
    self.nm.scan(hosts=target_ip, arguments=arguments)
    
    found_hosts = self.nm.all_hosts()
    if not found_hosts:
        return {"success": False, "error": "Host down"}
    
    real_ip = found_hosts[0]
    raw_data = self.nm[real_ip]
    
    return {
        "success": True,
        "ip": real_ip,
        "hostname": raw_data.hostname(),
        "state": raw_data.state(),
        "protocols": list(raw_data.all_protocols()),
        "full_data": raw_data
    }
```

**Nmap Parametreleri**:
- `-Pn`: Ping atma, direkt taramaya başla
- `-sV`: Servis versiyonlarını tespit et
- `--version-light`: Hafif versiyon tespiti (daha hızlı)

**Return Format**:
```json
{
  "success": true,
  "ip": "45.33.32.156",
  "hostname": "scanme.nmap.org",
  "state": "up",
  "protocols": ["tcp"],
  "full_data": {...}
}
```

---

### 5️⃣ Database Models (`app/models/scan_record.py`)

#### 📄 [`scan_record.py`](file:///c:/cyber_project/poirot_solution/poirot_api/app/models/scan_record.py)
**Amaç**: Tarama sonuçlarının veritabanı modeli

**Model: `ScanRecord`**

```python
class ScanRecord(db.Model):
    __tablename__ = 'scan_records'
    
    id = db.Column(db.Integer, primary_key=True)
    target_ip = db.Column(db.String(50), nullable=False)
    scan_type = db.Column(db.String(20), default='quick')
    raw_data = db.Column(JSONB, nullable=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

**Kolonlar**:

| Kolon | Tip | Açıklama |
|-------|-----|----------|
| `id` | Integer | Primary key (otomatik artan) |
| `target_ip` | String(50) | Taranan IP adresi |
| `scan_type` | String(20) | Tarama tipi (quick, full, vb.) |
| `raw_data` | JSONB | Nmap'ten gelen tüm data (JSON formatında) |
| `status` | String(20) | Durum: pending, completed, failed |
| `created_at` | DateTime | Oluşturulma zamanı (UTC) |

**JSONB Kullanımı**:
- PostgreSQL'e özel veri tipi
- JSON verisini binary formatta saklar
- İndekslenebilir ve sorgulanabilir

---

### 6️⃣ Frontend (`poirot_web/`)

#### 📄 [`templates/pages/home.html`](file:///c:/cyber_project/poirot_solution/poirot_web/templates/pages/home.html)
**Amaç**: Ana sayfa arayüzü

**Özellikler**:
- Bootstrap 5 ile responsive tasarım
- Input field: Hedef IP/domain girişi
- Scan button: Taramayı başlatma
- Result area: Tarama sonuçlarının gösterimi

**Template Inheritance**:
```html
{% extends "layouts/base.html" %}
{% block content %}
  <!-- Sayfa içeriği -->
{% endblock %}
```

#### 📄 `static/js/main.js`
**Amaç**: Frontend JavaScript logic

**Beklenen İşlevler**:
- Scan button'a click event listener
- AJAX request ile `/api/scan` endpoint'ine POST
- Sonuçları `#resultArea` div'ine yazdırma
- Hata yönetimi

**Örnek İş Akışı**:
```javascript
document.getElementById('scanBtn').addEventListener('click', async () => {
    const target = document.getElementById('targetInput').value;
    
    const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
    });
    
    const result = await response.json();
    // Sonuçları göster
});
```

---

## 🚀 Kurulum ve Çalıştırma

### Ön Gereksinimler

> [!IMPORTANT]
> Aşağıdaki yazılımların kurulu olması gerekiyor:

1. **Python 3.8+**
   - İndirme: [python.org](https://www.python.org/downloads/)
   - Kurulumda "Add to PATH" seçeneğini işaretleyin

2. **PostgreSQL 12+**
   - İndirme: [postgresql.org](https://www.postgresql.org/download/)
   - Kurulum sırasında şifre belirleyin (unutmayın!)

3. **Nmap**
   - İndirme: [nmap.org/download](https://nmap.org/download.html)
   - Windows installer'ı indirin ve kurun
   - Varsayılan yola (`C:\Program Files (x86)\Nmap`) kurun

4. **Git**
   - İndirme: [git-scm.com](https://git-scm.com/downloads/)

---

### Adım Adım Kurulum

#### 1. Projeyi Klonlama

```powershell
# Terminal veya PowerShell açın
cd C:\
git clone https://github.com/KULLANICI_ADINIZ/cyber_project.git
cd cyber_project
```

> [!TIP]
> GitHub'da repo oluşturmayı unutmayın!

#### 2. PostgreSQL Veritabanı Oluşturma

> [!IMPORTANT]
> PostgreSQL kurulumu sırasında belirlediğiniz **postgres kullanıcısının şifresini** unutmayın! Bu şifreyi `.env` dosyasında kullanacaksınız.

```powershell
# PostgreSQL'e bağlan (kurulumda belirlediğiniz şifreyi girin)
psql -U postgres
# Şifre: (PostgreSQL kurulumunda belirlediğiniz şifre)

# Veritabanını oluştur
CREATE DATABASE poirot_db;

# Çıkış
\q
```

**Alternatif (pgAdmin kullanarak)**:
1. pgAdmin4'ü açın (kurulum şifrenizi girin)
2. Sağ tık → Databases → Create → Database
3. İsim: `poirot_db`
4. Save

> [!TIP]
> PostgreSQL kurulumunda şifre belirlemediyseniz veya unuttuysanız, PostgreSQL'i yeniden yüklemeniz veya şifre sıfırlama yapmanız gerekebilir.

#### 3. Python Virtual Environment Oluşturma

```powershell
cd poirot_solution\poirot_api

# Virtual environment oluştur
python -m venv venv

# Aktive et (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Aktive et (Windows CMD)
.\venv\Scripts\activate.bat
```

> [!NOTE]
> PowerShell'de script execution hatası alırsanız:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

**Virtual Environment Aktif mi Kontrol**:
- Terminalinizde `(venv)` ibaresi görünmeli

#### 4. Python Bağımlılıklarını Yükleme

```powershell
pip install -r requirements.txt
```

**Beklenen Çıktı**:
```
Successfully installed flask-2.x.x python-dotenv-x.x.x ...
```

#### 5. `.env` Dosyasını Yapılandırma

> [!CAUTION]
> `.env` dosyasını **kendiniz oluşturmanız** gerekiyor! Bu dosya `.gitignore` içinde olduğu için repo'da bulunmaz.

**Dosya Oluşturma**: `poirot_api/.env` (yeni dosya)

```env
SECRET_KEY=rastgele-gizli-bir-anahtar-buraya-yazin
DATABASE_URL=postgresql://postgres:POSTGRESQL_SIFRENIZ@localhost/poirot_db
FLASK_APP=run.py
FLASK_DEBUG=1
```

**Önemli Değişiklikler**:

1. **SECRET_KEY**: Rastgele bir string yazın (örn: `poirot-super-secret-key-2026`)
2. **DATABASE_URL**: `POSTGRESQL_SIFRENIZ` yerine PostgreSQL kurulumunda belirlediğiniz şifreyi yazın

**Format Açıklaması**:
```
postgresql://KULLANICI:SIFRE@HOST:PORT/VERITABANI
           ↓         ↓      ↓     ↓    ↓
         postgres  ŞİFRENİZ localhost 5432 poirot_db
```

**Örnek (gerçek değerlerle)**:
```env
DATABASE_URL=postgresql://postgres:myPassword123@localhost/poirot_db
```

> [!WARNING]
> Şifrenizde özel karakterler (@, :, /, vb.) varsa URL encoding gerekebilir!

#### 6. Uygulamayı Çalıştırma

```powershell
# Virtual environment aktifken
python run.py
```

**Başarılı Çıktı**:
```
========================================
Bağlanılan Adres: postgresql://postgres:***@localhost/poirot_db
Hedef Veritabanı DOĞRU: poirot_db
Tablo oluşturma komutu gönderildi.
Veritabanındaki Mevcut Tablolar: ['scan_records']
BAŞARILI! 'scan_records' tablosu listede var.
========================================

 * Running on http://0.0.0.0:5000
 * Restarting with stat
```

#### 7. Tarayıcıda Test

1. Tarayıcınızı açın
2. Adres: `http://localhost:5000`
3. Ana sayfayı görmelisiniz
4. Test için: `scanme.nmap.org` girin ve "Taramayı Başlat" butonuna tıklayın

---

## 💻 Geliştirme Ortamı Hazırlığı

### Farklı Bir PC'de Çalışmak İçin

> [!IMPORTANT]
> Arkadaşlarınızın takip etmesi gereken adımlar:

#### A. İlk Kez Kurulum (Yeni Geliştirici)

1. **Ön gereksinimleri kur** (Python, PostgreSQL, Nmap, Git)

2. **Repo'yu klonla**:
```powershell
git clone https://github.com/KULLANICI_ADINIZ/cyber_project.git
cd cyber_project
```

3. **Veritabanını oluştur**:
```sql
CREATE DATABASE poirot_db;
```

4. **Virtual environment kur**:
```powershell
cd poirot_solution\poirot_api
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

5. **`.env` dosyası oluştur**:
```powershell
# poirot_api klasöründe .env dosyası oluşturun
cd poirot_solution\poirot_api
echo. > .env
# Ardından .env dosyasını bir editörle açın ve aşağıdaki içeriği ekleyin:
```

```env
SECRET_KEY=kendi-rastgele-anahtariniz
DATABASE_URL=postgresql://postgres:POSTGRESQL_KURULUM_SIFRENIZ@localhost/poirot_db
FLASK_APP=run.py
FLASK_DEBUG=1
```

> [!IMPORTANT]
> `POSTGRESQL_KURULUM_SIFRENIZ` yerine PostgreSQL'i kurarken belirlediğiniz şifreyi yazın!

6. **Çalıştır**:
```powershell
python run.py
```

#### B. Güncellemeleri Çekme

```powershell
# Ana branch'e geç
git checkout main

# Son değişiklikleri çek
git pull origin main

# Virtual environment'ı güncelle (gerekirse)
pip install -r requirements.txt

# Çalıştır
python run.py
```

#### C. Yeni Özellik Geliştirme

```powershell
# Yeni branch oluştur
git checkout -b yeni-ozellik-adi

# Kod değişikliklerini yap
# ...

# Değişiklikleri commit et
git add .
git commit -m "Yeni özellik: Açıklama"

# Branch'i push et
git push origin yeni-ozellik-adi

# GitHub'da Pull Request aç
```

---

## 🔄 Nasıl Çalışır?

### Tam İş Akışı Diyagramı

```mermaid
sequenceDiagram
    participant U as Kullanıcı
    participant B as Tarayıcı
    participant F as Flask API
    participant S as NmapScanner
    participant N as Nmap
    participant D as PostgreSQL

    U->>B: IP adresi gir ve "Taramayı Başlat"
    B->>F: POST /api/scan {target: "scanme.nmap.org"}
    F->>S: scanner.scan_target("scanme.nmap.org")
    S->>N: nmap -Pn -sV scanme.nmap.org
    N-->>S: Port ve servis bilgileri
    S-->>F: {success: true, ip, hostname, protocols, ...}
    F->>D: INSERT INTO scan_records (...)
    D-->>F: Kayıt başarılı
    F-->>B: JSON response
    B-->>U: Sonuçları ekranda göster
```

### Detaylı Akış Açıklaması

#### 1. Kullanıcı Girişi
- Kullanıcı web arayüzünde `scanme.nmap.org` girer
- "Taramayı Başlat" butonuna tıklar

#### 2. Frontend işlemi (JavaScript)
```javascript
// main.js içinde
fetch('/api/scan', {
    method: 'POST',
    body: JSON.stringify({target: 'scanme.nmap.org'})
})
```

#### 3. Backend Route (routes.py)
```python
@main.route('/api/scan', methods=['POST'])
def start_scan():
    target_ip = request.get_json().get('target')
    # ...
```

#### 4. Scanner Çağrısı (scanner.py)
```python
scanner = NmapScanner()
result = scanner.scan_target(target_ip)
```

#### 5. Nmap Taraması
```python
self.nm.scan(hosts=target_ip, arguments='-Pn -sV --version-light')
```

**Nmap Komut Satırı Eşdeğeri**:
```bash
nmap -Pn -sV --version-light scanme.nmap.org
```

#### 6. Sonuçların Dönüşü
```python
{
    "success": True,
    "ip": "45.33.32.156",
    "hostname": "scanme.nmap.org",
    "state": "up",
    "protocols": ["tcp"],
    "full_data": {
        "tcp": {
            22: {"state": "open", "name": "ssh"},
            80: {"state": "open", "name": "http"}
        }
    }
}
```

#### 7. Veritabanına Kayıt
```python
new_record = ScanRecord(
    target_ip=target_ip,
    status='completed',
    raw_data=result['full_data']
)
db.session.add(new_record)
db.session.commit()
```

**PostgreSQL Tablosu**:
```sql
SELECT * FROM scan_records;
```

| id | target_ip | scan_type | status | created_at | raw_data |
|----|-----------|-----------|--------|------------|----------|
| 1 | scanme.nmap.org | quick | completed | 2026-02-06 18:00:00 | {...} |

#### 8. Response Frontend'e
```json
{
  "success": true,
  "ip": "45.33.32.156",
  ...
}
```

#### 9. Ekranda Gösterim
- JavaScript sonuçları parse eder
- HTML elementlerine yazar
- Kullanıcı sonuçları görür

---

## 📝 Geliştirme Notları

### Güvenlik Notları

> [!CAUTION]
> Güvenlik için kritik noktalar:

1. **`.env` Dosyası**:
   - Asla Git'e eklemeyin
   - `.gitignore` içinde olduğundan emin olun
   - Her geliştiricinin kendi `.env` dosyası olmalı

2. **Veritabanı Şifreleri**:
   - Güçlü şifreler kullanın
   - Asla hardcode etmeyin

3. **Nmap Kullanımı**:
   - Sadece izin verilen sistemlerde tarama yapın
   - İzinsiz tarama yasadışıdır!

### Performans İyileştirmeleri

1. **Asenkron Tarama**:
   - Şu an taramalar senkron (blokluyor)
   - Celery + Redis kullanarak asenkron yapılabilir

2. **Caching**:
   - Aynı IP'nin tekrar taranmasını önlemek için cache eklenebilir
   - Redis veya Flask-Caching kullanılabilir

3. **Rate Limiting**:
   - Aynı kullanıcının sürekli tarama yapmasını engelleyin
   - Flask-Limiter kullanılabilir

### Hata Ayıklama (Debugging)

#### Problem: Uygulama Başlamıyor

**Çözüm 1: Port Meşgul**
```powershell
# Port 5000'i kontrol et
netstat -ano | findstr :5000

# İşlemi kapat (PID değerini kullan)
taskkill /PID <PID_NUMARASI> /F
```

**Çözüm 2: Veritabanı Bağlantısı**
```python
# config.py içinde debug aktif et
SQLALCHEMY_ECHO = True
```

**Çözüm 3: Nmap Bulunamıyor**
```powershell
# Nmap yolunu kontrol et
where nmap

# PATH'e manuel ekle (geçici)
$env:Path += ";C:\Program Files (x86)\Nmap"
```

#### Problem: Tarama Çalışmıyor

**Log Kontrolü**:
```python
# scanner.py içinde print ekle
print(f"Tarama başlatılıyor: {target_ip}")
print(f"Bulunan hostlar: {self.nm.all_hosts()}")
```

**Manuel Test**:
```powershell
# Terminal'de direkt çalıştır
nmap -Pn -sV scanme.nmap.org
```

### Test Senaryoları

#### 1. Unit Test Örneği

**Dosya**: `tests/test_scanner.py` (oluşturulabilir)
```python
import unittest
from app.core.scanner import NmapScanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NmapScanner()
    
    def test_scan_valid_target(self):
        result = self.scanner.scan_target('scanme.nmap.org')
        self.assertTrue(result['success'])
        self.assertIn('ip', result)
    
    def test_scan_invalid_target(self):
        result = self.scanner.scan_target('invalid.fake.domain.xyz')
        self.assertFalse(result['success'])

if __name__ == '__main__':
    unittest.main()
```

**Çalıştırma**:
```powershell
python -m unittest tests.test_scanner
```

#### 2. API Test

**Dosya**: [`test_api.py`](file:///c:/cyber_project/poirot_solution/poirot_api/test_api.py)
```powershell
python test_api.py
```

### Gelecek Geliştirmeler

#### Öncelik 1: Kullanıcı Yönetimi
- [ ] Kullanıcı kaydı ve login
- [ ] Her kullanıcının kendi tarama geçmişi
- [ ] Flask-Login kullanımı

#### Öncelik 2: Gelişmiş Tarama Seçenekleri
- [ ] Farklı tarama tipleri (full, stealth, aggressive)
- [ ] Port aralığı belirleme
- [ ] Tarama hızı kontrolü

#### Öncelik 3: Raporlama
- [ ] PDF rapor oluşturma
- [ ] Grafik ve istatistikler
- [ ] Tarama karşılaştırma

#### Öncelik 4: Real-time Updates
- [ ] WebSocket ile canlı tarama durumu
- [ ] Progress bar
- [ ] Flask-SocketIO kullanımı

### Kod Standartları

1. **Python PEP 8**:
   - 4 boşluk indentation
   - Satır uzunluğu max 79
   - Snake_case değişken isimleri

2. **Docstring Kullanımı**:
```python
def scan_target(self, target_ip, scan_type='quick'):
    """
    Hedef IP/domain'i tarar.
    
    Args:
        target_ip (str): Taranacak IP veya domain
        scan_type (str): Tarama tipi (quick, full)
    
    Returns:
        dict: Tarama sonuçları
    """
```

3. **Git Commit Mesajları**:
```
feat: Yeni özellik eklendi
fix: Bug düzeltildi
docs: Dokümantasyon güncellendi
refactor: Kod refactoring
test: Test eklendi
```

### Faydalı Komutlar

```powershell
# Virtual environment aktifleştirme
.\venv\Scripts\Activate.ps1

# Bağımlılıkları güncelleme
pip install --upgrade -r requirements.txt

# Yeni bağımlılık ekleme
pip install paket_adi
pip freeze > requirements.txt

# PostgreSQL'e bağlanma
psql -U postgres -d poirot_db

# Tabloları listeleme (psql içinde)
\dt

# Veritabanı dump alma
pg_dump -U postgres poirot_db > backup.sql

# Dump'ı geri yükleme
psql -U postgres -d poirot_db < backup.sql

# Flask shell (interaktif Python)
flask shell
>>> from app import db
>>> from app.models.scan_record import ScanRecord
>>> ScanRecord.query.all()
```

---

## 🎓 Öğrenme Kaynakları

### Python & Flask
- [Flask Resmi Dokümantasyonu](https://flask.palletsprojects.com/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/)
- [Python-nmap](https://xael.org/pages/python-nmap-en.html)

### Nmap
- [Nmap Resmi Kılavuzu](https://nmap.org/book/man.html)
- [Nmap Network Scanning](https://nmap.org/book/)

### PostgreSQL
- [PostgreSQL Tutorial](https://www.postgresqltutorial.com/)
- [JSONB Veri Tipi](https://www.postgresql.org/docs/current/datatype-json.html)

### Git & GitHub
- [Git Basics](https://git-scm.com/book/en/v2/Getting-Started-Git-Basics)
- [GitHub Flow](https://guides.github.com/introduction/flow/)

---

## 🤝 Katkıda Bulunma

Projeye katkıda bulunmak için:

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/harika-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'feat: Harika özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/harika-ozellik`)
5. Pull Request açın

---

## 📞 İletişim ve Destek

Sorularınız için:
- GitHub Issues üzerinden bildirim açabilirsiniz
- Proje maintainer'larına ulaşabilirsiniz

---

## 📜 Lisans

Bu proje eğitim amaçlıdır. Ticari kullanım öncesi lisans belirlenmelidir.

---

**Son Güncelleme**: 2026-02-06  
**Versiyon**: 1.0.0  
**Geliştiriciler İçin Hazırlandı** 🕵️‍♂️
