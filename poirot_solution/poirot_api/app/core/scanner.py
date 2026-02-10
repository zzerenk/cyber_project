import nmap
import os
import sys
import re
import platform # İşletim sistemini anlamak için şart!

class NmapScanner:
    def __init__(self):
        # 1. İşletim Sistemini Algıla
        sistem = platform.system()
        print(f"🖥️ Çalışan Sistem: {sistem}")

        # 2. Sadece Windows ise Path Ayarı Yap
        if sistem == "Windows":
            nmap_yolu_1 = r"C:\Program Files (x86)\Nmap"
            nmap_yolu_2 = r"C:\Program Files\Nmap"
            os.environ['PATH'] += ";" + nmap_yolu_1 + ";" + nmap_yolu_2
            print("Running in Windows Mode: Path eklendi.")
        
        try:
            self.nm = nmap.PortScanner()
            print("✅ Scanner Başlatıldı.")
        except nmap.PortScannerError:
            if sistem == "Linux":
                print("❌ HATA: Nmap bulunamadı. Lütfen 'sudo apt install nmap' yapın.")
            else:
                print("❌ HATA: Nmap Windows'ta bulunamadı. Yüklü olduğundan emin olun.")
            sys.exit(1)
        except Exception as e:
            print(f"🔥 Başlatma Hatası: {e}")
            raise

    def scan_target(self, target_ip, options={}):
            
            # 3. Girdi Temizliği (Input Sanitization) - Görünmez boşlukları siler
            if target_ip:
                target_ip = target_ip.strip().replace("'", "").replace('"', "")

            print(f"\n--- 🕵️‍♂️ TARAMA: {target_ip} ---")
        
            args = ["-Pn"] # Ping atma (Varsayılan)

            if options.get('detectOS'):
                args.append("-O")
                
            if options.get('serviceVersion'):
                args.append("-sV")
                args.append("--version-intensity 5")
                
            if options.get('vulnScan'):
                args.append("--script vuln")
                
            if options.get('speed') == 'aggressive':
                args.append("-T4") 
                # 🛑 DİKKAT: Sanal Makineyi (Kali) boğan ayar buydu!
                # args.append("--min-rate 1000")  <-- Bunu kaldırdık. 
                # T4 zaten yeterince hızlıdır ve paket kaybı yapmaz.
            
            if options.get('subdomainScan'):
                args.append("--script dns-brute")
                
            arguments_str = " ".join(args)
            print(f"⚙️ Çalıştırılan Komut: nmap {arguments_str} {target_ip}")
    
            try:
                # Taramayı başlat
                self.nm.scan(hosts=target_ip, arguments=arguments_str)
                
                # Host listesini kontrol et (DEBUG Ekledim)
                found_hosts = self.nm.all_hosts()
                print(f"📋 Bulunan Hostlar: {found_hosts}")

                if not found_hosts:
                    # Eğer host bulunamadıysa scaninfo'yu yazdıralım ki hatayı görelim
                    print(f"⚠️ Hata Detayı: {self.nm.scaninfo()}")
                    return {"success": False, "error": "Host down veya erişilemiyor (Host not found)."}

                # IP veya Domain karışıklığını önlemek için her zaman bulunan ilk IP'yi al
                real_ip = found_hosts[0]
                raw_data = self.nm[real_ip]
                
                # Veriyi topla
                summary = {
                    "success": True,
                    "ip": real_ip,
                    "hostname": raw_data.hostname() if raw_data.hostname() else target_ip,
                    "state": raw_data.state(),
                    "os_match": [],
                    "vulnerabilities": [],
                    "subdomains": [], # Subdomain listesi başlat
                    "full_data": raw_data
                }

                # 1. İşletim Sistemi
                if 'osmatch' in raw_data:
                    for os in raw_data['osmatch']:
                        summary['os_match'].append({
                            'name': os['name'],
                            'accuracy': os['accuracy']
                        })

                # 2. Zafiyetler ve Portlar
                if 'tcp' in raw_data:
                    for port, details in raw_data['tcp'].items():
                        if 'script' in details:
                            for script_name, output in details['script'].items():
                                
                                vuln_entry = {
                                    'port': port,
                                    'script': script_name,
                                    'raw_output': output,
                                    'parsed_data': []
                                }

                                if 'vulners' in script_name:
                                    regex_pattern = r'(CVE-\d{4}-\d+|SSV:\d+)\s+(\d+\.\d)\s+(https?://\S+)(.*)?'
                                    matches = re.findall(regex_pattern, output)
                                    
                                    for match in matches:
                                        vuln_entry['parsed_data'].append({
                                            'id': match[0],
                                            'score': float(match[1]),
                                            'link': match[2],
                                            'is_exploit': "*EXPLOIT*" in (match[3] if len(match) > 3 else "")
                                        })

                                summary['vulnerabilities'].append(vuln_entry)

                # 3. Subdomain Discovery Parsing
                if 'hostscript' in raw_data:
                    try:
                        for script in raw_data['hostscript']:
                            if script.get('id') == 'dns-brute':
                                output = script.get('output', '')
                                lines = output.strip().split('\n')
                                for line in lines:
                                    line = line.strip()
                                    if line and ' - ' in line:
                                        if line.startswith('DNS Brute') or line.startswith('force'):
                                            continue
                                        parts = line.split(' - ', 1)
                                        if len(parts) == 2:
                                            subdomain = parts[0].strip()
                                            ip = parts[1].strip()
                                            if '.' in subdomain:
                                                summary['subdomains'].append({
                                                    'domain': subdomain,
                                                    'ip': ip
                                                })
                    except Exception as e:
                        print(f"⚠️ Subdomain parsing error: {e}")

                return summary

            except Exception as e:
                print(f"🔥 KRİTİK HATA: {e}")
                return {"success": False, "error": str(e)}