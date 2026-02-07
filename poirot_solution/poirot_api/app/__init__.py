import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()  

def create_app(config_class=Config):
    # --- YOL HESAPLAMA ---
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_dir = os.path.dirname(base_dir)
    
    web_folder = os.path.join(root_dir, 'poirot_web')
    template_folder = os.path.join(web_folder, 'templates')
    static_folder = os.path.join(web_folder, 'static')

    app = Flask(__name__, 
                template_folder=template_folder,
                static_folder=static_folder)
    
    app.config.from_object(config_class)
 
    db.init_app(app) 
    from app.models.scan_record import ScanRecord

    with app.app_context():
        
        print("\n" + "="*40)
        
        #Nereye Bağlanıyoruz?
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        print(f"Bağlanılan Adres: {db_url}")
        
        #Hangi Veritabanı Dosyası?
        if "/poirot_db" in db_url:
            print("Hedef Veritabanı DOĞRU: poirot_db")
        else:
            print("Hedef Veritabanı YANLIŞ!")

        # Tabloyu Oluşturmayı Dene
        try:
            db.create_all()
            print("Tablo oluşturma komutu gönderildi.")
            
            #Tablo gerçekten oluştu mu?
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"Veritabanındaki Mevcut Tablolar: {tables}")
            
            if 'scan_records' in tables:
                print("BAŞARILI! 'scan_records' tablosu listede var.")
            else:
                print("HATA! Komut çalıştı ama tablo listede yok.")
                
        except Exception as e:
            print(f"BİR HATA OLUŞTU: {e}")
            
        print("="*40 + "\n")

    # --- Rotaları Ekleme ---
    from app.api.routes import api 
    app.register_blueprint(api)

    return app