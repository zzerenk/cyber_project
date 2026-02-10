import nmap
import os
import sys
import re
import platform

class NmapScanner:
    def __init__(self):
        sistem = platform.system()
        print(f"🖥️ Çalışan Sistem: {sistem}")

        if sistem == "Windows":
            nmap_yolu_1 = r"C:\Program Files (x86)\Nmap"
            nmap_yolu_2 = r"C:\Program Files\Nmap"
            os.environ['PATH'] += ";" + nmap_yolu_1 + ";" + nmap_yolu_2
        
        try:
            self.nm = nmap.PortScanner()
            print("✅ Scanner Başlatıldı.")
        except Exception as e:
            print(f"🔥 Başlatma Hatası: {e}")
            raise

    def scan_target(self, target_ip, options={}):
            
            # Girdi Temizliği (Kali'de Hayat Kurtarır)
            if target_ip:
                target_ip = target_ip.strip().replace("'", "").replace('"', "")

            print(f"\n--- 🕵️‍♂️ TARAMA BAŞLIYOR: {target_ip} ---")
        
            # --- 🚀 PROFESYONEL AYARLAR ---
            args = ["-Pn"] # Ping atma, direkt dal.

            # 1. Servis Versiyonlarını Zorla (Service Names için Kritik)
            # --version-all: Her probu dene, servisin adını mutlaka bul.
            if options.get('serviceVersion'):
                args.append("-sV")
                args.append("--version-intensity 9") # 0-9 arası. 9 en detaylısıdır.
                args.append("--version-all") 

            # 2. İşletim Sistemi (OS)
            if options.get('detectOS'):
                args.append("-O")
                # --osscan-guess: Tam eşleşme yoksa en yakın tahmini zorla
                args.append("--osscan-guess") 

            # 3. Hız ve Güvenilirlik (Kali VM Ayarı)
            if options.get('speed') == 'aggressive':
                # -T4: Hızlı ama güvenli.
                # --max-retries 2: Paket kaybolursa 2 kere daha dene (VMware için şart!)
                args.append("-T4") 
                args.append("--max-retries 2")
            
            # 4. Zafiyet ve Subdomain
            if options.get('vulnScan'): args.append("--script vuln")
            if options.get('subdomainScan'): args.append("--script dns-brute")
                
            arguments_str = " ".join(args)
            print(f"⚙️ Komut: nmap {arguments_str} {target_ip}")
    
            try:
                self.nm.scan(hosts=target_ip, arguments=arguments_str)
                
                # Sonuç Kontrolü
                if not self.nm.all_hosts():
                    return {"success": False, "error": "Host down/erişilemiyor."}

                real_ip = self.nm.all_hosts()[0]
                raw_data = self.nm[real_ip]
                
                summary = {
                    "success": True,
                    "ip": real_ip,
                    "hostname": raw_data.hostname() if raw_data.hostname() else target_ip,
                    "state": raw_data.state(),
                    "os_match": [],
                    "vulnerabilities": [],
                    "open_ports": [], # Port detayları için
                    "subdomains": [],
                    "full_data": raw_data
                }

                # OS Parse
                if 'osmatch' in raw_data:
                    for os in raw_data['osmatch']:
                        summary['os_match'].append({
                            'name': os['name'],
                            'accuracy': os['accuracy']
                        })

                # Port ve Servis Detayları (İsimler Burada!)
                if 'tcp' in raw_data:
                    for port, details in raw_data['tcp'].items():
                        
                        # Servis Adını ve Versiyonunu Çek
                        port_info = {
                            'port': port,
                            'protocol': 'tcp',
                            'state': details.get('state', 'unknown'),
                            'service': details.get('name', 'unknown'), # http, ssh vs.
                            'product': details.get('product', ''),     # Apache vs.
                            'version': details.get('version', '')      # 2.4.41 vs.
                        }
                        summary['open_ports'].append(port_info)

                        # Zafiyet Scriptleri
                        if 'script' in details:
                            for script_name, output in details['script'].items():
                                vuln_entry = {
                                    'port': port,
                                    'script': script_name,
                                    'raw_output': output,
                                    'parsed_data': []
                                }
                                if 'vulners' in script_name:
                                    regex = r'(CVE-\d{4}-\d+|SSV:\d+)\s+(\d+\.\d)\s+(https?://\S+)(.*)?'
                                    matches = re.findall(regex, output)
                                    for match in matches:
                                        vuln_entry['parsed_data'].append({
                                            'id': match[0],
                                            'score': float(match[1]),
                                            'link': match[2],
                                            'is_exploit': "*EXPLOIT*" in (match[3] if len(match)>3 else "")
                                        })
                                summary['vulnerabilities'].append(vuln_entry)

                # Subdomains
                if 'hostscript' in raw_data:
                    for script in raw_data['hostscript']:
                        if script.get('id') == 'dns-brute':
                            lines = script.get('output', '').strip().split('\n')
                            for line in lines:
                                if ' - ' in line and not line.startswith(('DNS', 'force')):
                                    parts = line.split(' - ', 1)
                                    if len(parts) == 2 and '.' in parts[0]:
                                        summary['subdomains'].append({'domain': parts[0].strip(), 'ip': parts[1].strip()})

                return summary

            except Exception as e:
                print(f"🔥 KRİTİK HATA: {e}")
                return {"success": False, "error": str(e)}