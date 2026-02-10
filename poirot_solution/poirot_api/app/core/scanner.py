import nmap
import os
import sys
import re

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

    def scan_target(self, target_ip, options={}):
            
            print(f"\n--- 🕵️‍♂️ TARAMA: {target_ip} ---")
        
            # Argümanları dinamik olarak inşa edelim
            args = ["-Pn"] # Ping atma (Varsayılan)

            # Kullanıcı arayüzünden gelen seçenekler
            if options.get('detectOS'):
                args.append("-O") # İşletim Sistemi
                
            if options.get('serviceVersion'):
                args.append("-sV") # Servis Versiyonu
                args.append("--version-intensity 5")
                
            if options.get('vulnScan'):
                args.append("--script vuln") # Zafiyet Taraması
                
            if options.get('speed') == 'aggressive':
                args.append("-T4") # Hızlı Mod
                args.append("--min-rate 1000")
            if options.get('subdomainScan'):
                args.append("--script dns-brute")
                
            # Listeyi string'e çevir (Örn: "-Pn -sV -O -T4")
            arguments_str = " ".join(args)
            print(f"⚙️ Çalıştırılan Komut: nmap {arguments_str} {target_ip}")
    

            try:
                # Taramayı başlat
                self.nm.scan(hosts=target_ip, arguments=arguments_str)
                
                # Host listesini kontrol et
                found_hosts = self.nm.all_hosts()
                if not found_hosts:
                    return {"success": False, "error": "Host down veya erişilemiyor."}

                real_ip = found_hosts[0]
                raw_data = self.nm[real_ip]
                
                # Veriyi topla
                summary = {
                    "success": True,
                    "ip": real_ip,
                    "hostname": raw_data.hostname(),
                    "state": raw_data.state(),
                    "os_match": [], # İşletim sistemi tahminlerini buraya atacağız
                    "vulnerabilities": [], # Bulunan açıkları buraya atacağız
                    "full_data": raw_data
                }

                # 1. İşletim Sistemi Bilgisini Çek (OS Detection)
                if 'osmatch' in raw_data:
                    for os in raw_data['osmatch']:
                        summary['os_match'].append({
                            'name': os['name'],
                            'accuracy': os['accuracy']
                        })

                # ZAFİYETLERİ PARSE ETME (DÜZENLEME BURADA)
                if 'tcp' in raw_data:
                    for port, details in raw_data['tcp'].items():
                        if 'script' in details:
                            for script_name, output in details['script'].items():
                                
                                # Ham veriyi yine de saklayalım (ne olur ne olmaz)
                                vuln_entry = {
                                    'port': port,
                                    'script': script_name,
                                    'raw_output': output,
                                    'parsed_data': [] # Ayıkladığımız veriler buraya gelecek
                                }

                                # Eğer script 'vulners' ise özel parse işlemi yapalım
                                if 'vulners' in script_name:
                                    # Regex Büyüsü: CVE, Puan ve Linki yakalar
                                    # Örn: CVE-2023-38408  9.8  https://...
                                    regex_pattern = r'(CVE-\d{4}-\d+|SSV:\d+)\s+(\d+\.\d)\s+(https?://\S+)(.*)?'
                                    matches = re.findall(regex_pattern, output)
                                    
                                    for match in matches:
                                        cve_id = match[0]
                                        score = float(match[1])
                                        link = match[2]
                                        is_exploit = "*EXPLOIT*" in match[3] if len(match) > 3 else False

                                        vuln_entry['parsed_data'].append({
                                            'id': cve_id,
                                            'score': score,
                                            'link': link,
                                            'is_exploit': is_exploit
                                        })

                                summary['vulnerabilities'].append(vuln_entry)

                # 3. SUBDOMAIN DISCOVERY PARSING (CRITICAL ADDITION)
                # dns-brute results are in 'hostscript', NOT in 'tcp'
                summary['subdomains'] = []
                
                if 'hostscript' in raw_data:
                    try:
                        for script in raw_data['hostscript']:
                            if script.get('id') == 'dns-brute':
                                output = script.get('output', '')
                                # Parse each line: format is usually "subdomain.domain.com - IP.ADDRESS"
                                lines = output.strip().split('\n')
                                for line in lines:
                                    line = line.strip()
                                    
                                    # Filter out header/description lines
                                    # Only process lines with " - " (space hyphen space)
                                    if line and ' - ' in line:
                                        # Ignore header lines that start with "DNS Brute" or contain "force"
                                        if line.startswith('DNS Brute') or line.startswith('force'):
                                            continue
                                        
                                        # Match pattern: subdomain - IP
                                        parts = line.split(' - ', 1)
                                        if len(parts) == 2:
                                            subdomain = parts[0].strip()
                                            ip = parts[1].strip()
                                            
                                            # Validate: subdomain must contain a dot to be valid
                                            if '.' in subdomain:
                                                summary['subdomains'].append({
                                                    'domain': subdomain,
                                                    'ip': ip
                                                })
                    except Exception as e:
                        print(f"⚠️ Subdomain parsing error: {e}")
                        # Continue execution even if subdomain parsing fails

                return summary

            except Exception as e:
                print(f"🔥 KRİTİK HATA: {e}")
                return {"success": False, "error": str(e)}