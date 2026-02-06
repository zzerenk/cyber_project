import nmap
import os
import sys

class NmapScanner:
    def __init__(self):
        # Nmap yollarını zorla ekle (Senin çalışan ayarın)
        nmap_yolu_1 = r"C:\Program Files (x86)\Nmap"
        nmap_yolu_2 = r"C:\Program Files\Nmap"
        os.environ['PATH'] += ";" + nmap_yolu_1 + ";" + nmap_yolu_2
        
        try:
            self.nm = nmap.PortScanner()
            print("Scanner Başlatıldı.")
        except Exception as e:
            print(f"Başlatma Hatası: {e}")
            raise

    def scan_target(self, target_ip, scan_type='quick'):
        print(f"\n--- 🕵️‍♂️ DETAYLI İNCELEME BAŞLIYOR: {target_ip} ---")
        try:
            arguments = '-Pn -sV --version-light'
            
            # Taramayı yap
            self.nm.scan(hosts=target_ip, arguments=arguments)
            
            # Bulunan hostları listeye al
            found_hosts = self.nm.all_hosts()
            print(f"🏠 Bulunan Hostlar: {found_hosts}")

            # KONTROL DEĞİŞİKLİĞİ BURADA:
            # İsme değil, listenin dolu olup olmadığına bakıyoruz.
            if not found_hosts:
                print("❌ HATA: Hiçbir host bulunamadı.")
                return {"success": False, "error": "Host down veya erişilemiyor."}

            # Listeden İLK sıradaki IP'yi alıyoruz (Artık ismin ne olduğu önemsiz)
            # scanme.nmap.org girdin ama ip '45.33...' geldi. Onu yakalıyoruz.
            real_ip = found_hosts[0]
            
            # Veriyi o IP üzerinden çekiyoruz
            raw_data = self.nm[real_ip]
            
            summary = {
                "success": True,
                "ip": real_ip, # Gerçek IP'yi kaydedelim
                "hostname": raw_data.hostname(),
                "state": raw_data.state(),
                "protocols": list(raw_data.all_protocols()),
                "full_data": raw_data 
            }
            return summary

        except Exception as e:
            print(f"🔥 KRİTİK HATA: {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}