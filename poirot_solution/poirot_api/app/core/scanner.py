import nmap
import re

class NmapScanner:
    def __init__(self):
        """
        Initialize Nmap Scanner for Linux/Kali environment.
        No hardcoded Windows paths - assumes nmap is in system PATH.
        """
        try:
            self.nm = nmap.PortScanner()
            print("[SCANNER] Nmap initialized successfully.")
        except nmap.PortScannerError as e:
            print(f"[ERROR] Nmap not found in PATH: {e}")
            print("[HINT] Install nmap: sudo apt install nmap")
            raise
        except Exception as e:
            print(f"[ERROR] Scanner initialization failed: {e}")
            raise

    def scan_target(self, target_ip, options={}):
        """
        Perform comprehensive Nmap scan with dynamic options.
        
        Args:
            target_ip (str): IP address or hostname to scan
            options (dict): Scan configuration options
            
        Returns:
            dict: Structured scan results with success status
        """
        print(f"\n{'='*60}")
        print(f"[SCAN] Target: {target_ip}")
        print(f"{'='*60}")
    
        # Build dynamic Nmap arguments
        args = ["-Pn"]  # Skip ping (default)

        # User-configured scan options
        if options.get('detectOS'):
            args.append("-O")
            print("[CONFIG] OS Detection enabled (-O)")
            
        if options.get('serviceVersion'):
            args.append("-sV")
            args.append("--version-intensity 5")
            print("[CONFIG] Service Version Detection enabled (-sV)")
            
        if options.get('vulnScan'):
            args.append("--script vuln")
            print("[CONFIG] Vulnerability Scanning enabled (--script vuln)")
            
        if options.get('speed') == 'aggressive':
            args.append("-T4")
            args.append("--min-rate 1000")
            print("[CONFIG] Aggressive timing mode enabled (-T4)")
            
        if options.get('subdomainScan'):
            args.append("--script dns-brute")
            print("[CONFIG] Subdomain Discovery enabled (--script dns-brute)")
            
        # Convert arguments list to string
        arguments_str = " ".join(args)
        print(f"[NMAP] Command: nmap {arguments_str} {target_ip}")
        print(f"{'='*60}\n")

        try:
            # Execute Nmap scan
            self.nm.scan(hosts=target_ip, arguments=arguments_str)
            
            # === DEEP DEBUG LOGGING (CRITICAL FOR TROUBLESHOOTING) ===
            print("\n" + "="*60)
            print("[DEBUG] Scan completed. Analyzing results...")
            print("="*60)
            
            # Check what hosts were found
            found_hosts = self.nm.all_hosts()
            print(f"[DEBUG] all_hosts() returned: {found_hosts}")
            print(f"[DEBUG] Number of hosts found: {len(found_hosts)}")
            
            # Print scan metadata
            try:
                scan_info = self.nm.scaninfo()
                print(f"[DEBUG] scaninfo(): {scan_info}")
            except Exception as e:
                print(f"[DEBUG] Could not retrieve scaninfo: {e}")
            
            # Check for Nmap errors
            if hasattr(self.nm, 'stderr') and self.nm.stderr:
                print(f"[DEBUG] Nmap STDERR: {self.nm.stderr}")
            
            # === CRITICAL FIX: Use first found host, not input target ===
            if not found_hosts:
                print("[ERROR] No hosts found in scan results!")
                print("[HINT] Host might be down, blocked, or unreachable.")
                if hasattr(self.nm, 'stderr'):
                    print(f"[NMAP ERROR] {self.nm.stderr}")
                return {
                    "success": False, 
                    "error": "Host down or unreachable. No scan results returned."
                }

            # Use the FIRST host found (fixes hostname -> IP mismatch)
            real_ip = found_hosts[0]
            print(f"[DEBUG] Using host key: '{real_ip}' (resolved from '{target_ip}')")
            
            raw_data = self.nm[real_ip]
            print(f"[DEBUG] raw_data keys: {list(raw_data.keys())}")
            print("="*60 + "\n")
            
            # Build structured response
            summary = {
                "success": True,
                "ip": real_ip,
                "hostname": raw_data.hostname(),
                "state": raw_data.state(),
                "os_match": [],
                "vulnerabilities": [],
                "subdomains": [],
                "full_data": raw_data
            }

            # === 1. OPERATING SYSTEM DETECTION ===
            if 'osmatch' in raw_data:
                print(f"[PARSER] Found {len(raw_data['osmatch'])} OS matches")
                for os in raw_data['osmatch']:
                    summary['os_match'].append({
                        'name': os['name'],
                        'accuracy': os['accuracy']
                    })

            # === 2. VULNERABILITY PARSING ===
            if 'tcp' in raw_data:
                vuln_count = 0
                for port, details in raw_data['tcp'].items():
                    if 'script' in details:
                        for script_name, output in details['script'].items():
                            
                            vuln_entry = {
                                'port': port,
                                'script': script_name,
                                'raw_output': output,
                                'parsed_data': []
                            }

                            # Parse 'vulners' script for CVE data
                            if 'vulners' in script_name:
                                # Regex: CVE-YYYY-NNNNN  SCORE  URL
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
                                    vuln_count += 1

                            summary['vulnerabilities'].append(vuln_entry)
                
                if vuln_count > 0:
                    print(f"[PARSER] Found {vuln_count} vulnerabilities")

            # === 3. SUBDOMAIN DISCOVERY PARSING ===
            if 'hostscript' in raw_data:
                try:
                    for script in raw_data['hostscript']:
                        if script.get('id') == 'dns-brute':
                            output = script.get('output', '')
                            lines = output.strip().split('\n')
                            subdomain_count = 0
                            
                            for line in lines:
                                line = line.strip()
                                
                                # Filter: Only lines with " - " (space-hyphen-space)
                                if line and ' - ' in line:
                                    # Ignore header lines
                                    if line.startswith('DNS Brute') or line.startswith('force'):
                                        continue
                                    
                                    # Parse: subdomain - IP
                                    parts = line.split(' - ', 1)
                                    if len(parts) == 2:
                                        subdomain = parts[0].strip()
                                        ip = parts[1].strip()
                                        
                                        # Validate: subdomain must contain a dot
                                        if '.' in subdomain:
                                            summary['subdomains'].append({
                                                'domain': subdomain,
                                                'ip': ip
                                            })
                                            subdomain_count += 1
                            
                            if subdomain_count > 0:
                                print(f"[PARSER] Found {subdomain_count} subdomains")
                                
                except Exception as e:
                    print(f"[WARNING] Subdomain parsing error: {e}")
                    # Continue execution even if subdomain parsing fails

            print(f"[SUCCESS] Scan results compiled for {real_ip}\n")
            return summary

        except Exception as e:
            print(f"\n[CRITICAL ERROR] Scan failed: {e}")
            return {
                "success": False, 
                "error": str(e)
            }