import os
import time
import sqlite3
import requests
import yaml
import logging
import feedparser
import re
import dns.resolver
from bs4 import BeautifulSoup
from datetime import datetime, timedelta

# --- LOGGING ---
from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler("monitor.log", maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class projectxMonitorV2:
    def __init__(self, config_path="config.yaml"):
        self.load_config(config_path)
        self.init_db()
        if not os.path.exists(self.config["report_dir"]):
            os.makedirs(self.config["report_dir"])
        self.recent_dns_resolutions = []
        self.recent_correlation_findings = []

    def load_config(self, path):
        with open(path, "r") as f:
            self.config = yaml.safe_load(f)

    def init_db(self):
        self.conn = sqlite3.connect(self.config["db_path"])
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                title TEXT,
                source TEXT,
                timestamp DATETIME,
                confidence REAL,
                meta TEXT
            )
        ''')
        self.conn.commit()

    def calculate_confidence(self, text):
        text = text.lower()
        
        # Check required terms
        if not all(term in text for term in self.config["semantic_filter"]["required_terms"]):
            return 0.0
            
        # Check excluded terms
        if any(term in text for term in self.config["semantic_filter"]["exclude_terms"]):
            return 0.1
            
        score = 0.5
        high_signal = self.config["semantic_filter"]["high_signal_terms"]
        for term in high_signal:
            if term in text:
                score += 0.1
                
        return min(1.0, score)

    def add_finding(self, url, title, source, text_for_filter):
        confidence = self.calculate_confidence(text_for_filter)
        if confidence < self.config["semantic_filter"]["confidence_threshold"]:
            logging.debug(f"Filtered out (low confidence {confidence}): {title}")
            return False

        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO findings (url, title, source, timestamp, confidence, meta)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (url, title, source, datetime.now(), confidence, ""))
            self.conn.commit()
            logging.info(f"New high-signal finding [{confidence}]: {title}")
            
            # Alerting for high confidence
            if confidence > 0.7:
                self.write_alert(title, url, source, confidence)
                
            return True
        except sqlite3.IntegrityError:
            return False

    def write_alert(self, title, url, source, confidence):
        try:
            alert_path = "alert.txt"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = f"🚨 *projectx OSINT Alert* 🚨\n\n*Title:* {title}\n*Source:* {source}\n*Confidence:* {confidence}\n*URL:* {url}"
            
            # Local log
            with open(alert_path, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] ALERT: {title}\n")
                f.write(f"Source: {source} | Confidence: {confidence} | URL: {url}\n\n")
            
            self.add_to_daily_buffer("alerts", f"[{confidence}] {title} - {url}")
                
            # Telegram Alert
            tg_config = self.config.get("alerting", {})
            bot_token = tg_config.get("telegram_token")
            chat_id = tg_config.get("telegram_chat_id")
            
            if bot_token and chat_id:
                tg_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = {
                    "chat_id": chat_id,
                    "text": msg,
                    "parse_mode": "Markdown"
                }
                requests.post(tg_url, json=payload, timeout=5)
                
        except Exception as e:
            logging.error(f"Failed to write alert: {e}")
            
    def is_new_item(self, category, item):
        import json
        cache_file = "seen_cache.json"
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
            
        items = data.setdefault(category, [])
        if item in items: return False
        
        items.append(item)
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return True

    def add_to_daily_buffer(self, category, item):
        if not self.is_new_item(category, item): return
        import json
        buffer_file = "daily_buffer.json"
        try:
            with open(buffer_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
            
        data.setdefault(category, []).append(item)
        with open(buffer_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def scan_rss(self):
        logging.info("[Phase 1] Scanning RSS feeds...")
        for source in self.config["sources"]:
            if source["type"] == "rss":
                try:
                    feed = feedparser.parse(source["url"])
                    for entry in feed.entries:
                        full_text = f"{entry.title} {entry.get('description', '')} {entry.get('summary', '')}"
                        self.add_finding(entry.link, entry.title, source["name"], full_text)
                except Exception as e:
                    logging.error(f"Error parsing RSS {source['name']}: {e}")

    def scan_github(self):
        logging.info("[Phase 1] Scanning GitHub Public API...")
        for source in self.config["sources"]:
            if source["type"] == "github_api":
                for query in source.get("queries", []):
                    try:
                        # Public search API, no auth required, rate limited
                        url = f"https://api.github.com/search/code?q={requests.utils.quote(query)}"
                        headers = {"Accept": "application/vnd.github.v3+json"}
                        response = requests.get(url, headers=headers)
                        if response.status_code == 200:
                            data = response.json()
                            for item in data.get("items", [])[:5]: # Top 5 to avoid noise
                                title = f"GitHub Code Match: {item['name']} in {item['repository']['full_name']}"
                                link = item["html_url"]
                                self.add_finding(link, title, "GitHub API", title + query)
                        elif response.status_code == 403:
                            logging.warning("GitHub API rate limit exceeded.")
                    except Exception as e:
                        logging.error(f"Error querying GitHub API for {query}: {e}")
        
        # Minitask 2: GitHub Events API scan for sk-ant-api
        logging.info("[Phase 1] Scanning GitHub Events API for leak patterns...")
        try:
            events_url = "https://api.github.com/events"
            headers = {"Accept": "application/vnd.github.v3+json"}
            resp = requests.get(events_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                events = resp.json()
                for event in events:
                    if event.get("type") == "PushEvent":
                        repo_name = event.get("repo", {}).get("name", "Unknown")
                        payload = event.get("payload", {})
                        commits = payload.get("commits", [])
                        for commit in commits:
                            msg = commit.get("message", "").lower()
                            if "sk-ant-api" in msg or ".env" in msg or ".key" in msg:
                                link = f"https://github.com/{repo_name}/commit/{commit.get('sha')}"
                                title = f"Suspicious PushEvent in {repo_name}"
                                # Add finding with sk-ant-api to trigger semantic filter if it matches
                                self.add_finding(link, title, "GitHub Events API", f"Commit message contains sk-ant-api or env/key references: {msg}")
        except Exception as e:
            logging.error(f"Error scanning GitHub Events API: {e}")

    def scan_telegram(self):
        logging.info("[Phase 1] Scanning Public Telegram Channels...")
        for source in self.config["sources"]:
            if source["type"] == "telegram_web":
                for channel in source.get("channels", []):
                    try:
                        url = f"https://t.me/s/{channel}"
                        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            messages = soup.find_all('div', class_='tgme_widget_message_text')
                            for msg in messages[-5:]: # Get latest 5 messages
                                text = msg.text
                                link = f"tg://resolve?domain={channel}"
                                title = f"Telegram Mention in @{channel}"
                                self.add_finding(link, title, "Telegram Web", text)
                    except Exception as e:
                        logging.error(f"Error scraping Telegram channel {channel}: {e}")

    def scan_crtsh(self):
        logging.info("[Phase 1] Scanning crt.sh for Historical Subdomains...")
        discovered_domains = set()
        for source in self.config["sources"]:
            if source["type"] == "crtsh_api":
                try:
                    response = requests.get(source["url"], timeout=15)
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            # name_value can contain newlines for multiple domains in one cert
                            for domain in name_value.split("\n"):
                                domain = domain.strip().lower()
                                if domain.endswith("targetcorp.com") and not domain.startswith("*"):
                                    discovered_domains.add(domain)
                except Exception as e:
                    logging.error(f"Error querying crt.sh: {e}")
        
        if discovered_domains:
            logging.info(f"crt.sh scan discovered {len(discovered_domains)} subdomains.")
            return list(discovered_domains)
        return []

    def is_possible_cdn(self, ip_str):
        # A simple heuristic check for demonstration purposes.
        # Cloudflare commonly uses 104.x.x.x, 172.64.x.x, etc. AWS uses various ranges.
        if ip_str.startswith("104.") or ip_str.startswith("172.64.") or ip_str.startswith("18.160."):
            return True
        return False

    def discover_dns(self):
        logging.info("[Phase 2] Performing DNS Discovery...")
        base_domain = self.config["target_domains"]["base"]
        
        if self.config["target_domains"].get("use_crtsh_data", False):
            logging.info("Using crt.sh data instead of manual list.")
            subdomains = self.scan_crtsh()
            targets = subdomains # They are already full domain names
        else:
            subdomains = self.config["target_domains"].get("hypothetical_subdomains", [])
            targets = [f"{sub}.{base_domain}" for sub in subdomains]
        
        resolved_endpoints = []
        for target in targets:
            try:
                # Only performing a DNS lookup, no HTTP connection
                answers = dns.resolver.resolve(target, 'A')
                ips = [rdata.address for rdata in answers]
                
                cdn_flags = []
                for ip in ips:
                    if self.is_possible_cdn(ip):
                        cdn_flags.append(f"{ip} (posible CDN o falso positivo)")
                    else:
                        cdn_flags.append(ip)
                        
                msg = f"DNS Resolution Successful for {target}: {ips}"
                logging.info(msg)
                self.add_finding(f"dns://{target}", f"Subdomain Discovered: {target}", "DNS Resolver", msg)
                
                self.recent_dns_resolutions.append({
                    "target": target,
                    "ips": cdn_flags
                })
                resolved_endpoints.append({"domain": target, "ips": ips})
                self.add_to_daily_buffer("subdomains", target)
            except dns.resolver.NXDOMAIN:
                logging.debug(f"DNS NXDOMAIN: {target}")
            except Exception as e:
                logging.debug(f"DNS Lookup failed for {target}: {e}")
        return resolved_endpoints

    def extract_codenames(self, domains):
        import re
        ignore_words = {"api", "com", "www", "staging", "internal", "TargetCorp", "proxy", "cdn", "assets", "docs", "support", "status", "legal", "resources", "partner", "sso", "stg", "prod", "dev", "test"}
        codenames = set()
        for domain in domains:
            parts = re.split(r'[\.-]', domain)
            for part in parts:
                word = part.lower().strip()
                # Exclude purely numeric parts, short strings, and common keywords
                if word and not word.isdigit() and len(word) > 2 and word not in ignore_words:
                    codenames.add(word)
        
        if codenames:
            try:
                with open("internal_codenames.txt", "w", encoding="utf-8") as f:
                    for name in sorted(codenames):
                        f.write(f"{name}\n")
                logging.info(f"Extracted {len(codenames)} internal codenames to internal_codenames.txt")
            except Exception as e:
                logging.error(f"Failed to write internal codenames: {e}")

    def scan_wayback(self, domains):
        logging.info("[Phase 1.5] Scanning Wayback Machine...")
        for domain in domains:
            try:
                url = f"https://archive.org/wayback/available?url=https://{domain}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    snapshots = data.get("archived_snapshots", {})
                    if "closest" in snapshots:
                        snap_status = snapshots["closest"].get("status")
                        snap_url = snapshots["closest"].get("url")
                        snap_time = snapshots["closest"].get("timestamp")
                        
                        msg = f"[Wayback] {domain} has a snapshot: {snap_url} ({snap_time}) - Status: {snap_status}"
                        logging.info(msg)
                        self.recent_correlation_findings.append(msg)
                        
                        if snap_status == "200":
                            with open("historic_endpoints.txt", "a", encoding="utf-8") as f:
                                f.write(f"{snap_url}\n")
                            
                            # Minitask 3: Analyze historical headers
                            try:
                                head_resp = requests.head(snap_url, timeout=10, allow_redirects=True)
                                if head_resp.status_code == 200:
                                    server = head_resp.headers.get("X-Archive-Orig-Server", "Unknown")
                                    ctype = head_resp.headers.get("X-Archive-Orig-Content-Type", "Unknown")
                                    powered_by = head_resp.headers.get("X-Archive-Orig-X-Powered-By", "None")
                                    cf_ray = head_resp.headers.get("X-Archive-Orig-CF-Ray", "None")
                                    
                                    header_msg = f"[Header Evolution] {domain} ({snap_time}): Server: {server}, Content-Type: {ctype}"
                                    if powered_by != "None": header_msg += f", X-Powered-By: {powered_by}"
                                    if cf_ray != "None": header_msg += f", CF-Ray: {cf_ray}"
                                    
                                    logging.info(header_msg)
                                    self.recent_correlation_findings.append(header_msg)
                                    self.add_to_daily_buffer("wayback", header_msg)
                            except Exception as he:
                                logging.debug(f"Wayback Header error for {domain}: {he}")
            except Exception as e:
                logging.debug(f"Wayback error for {domain}: {e}")

    def scan_shodan(self, ips):
        logging.info("[Phase 1.5] Scanning Shodan...")
        api_key = self.config.get("osint_apis", {}).get("shodan_api_key")
        if not api_key: return
        for ip in ips:
            if ip.startswith("10.") or ip.startswith("192.168."): continue
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    ports = data.get("ports", [])
                    org = data.get("org", "Unknown")
                    msg = f"[Shodan] Public IP {ip} ({org}) has ports open: {ports}"
                    logging.info(msg)
                    self.recent_correlation_findings.append(msg)
            except Exception:
                pass

    def geolocate_ips(self, ips):
        logging.info("[Phase 1.5] Geolocating Public IPs...")
        import time
        # ip-api allows 45 requests per minute -> ~1.3 seconds per request
        for ip in ips:
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                continue
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,as"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        country = data.get("country", "")
                        city = data.get("city", "")
                        org = data.get("org", "")
                        asn = data.get("as", "")
                        msg = f"[GeoIP] IP pública {ip} -> país: {country}, ciudad: {city}, organización: {org}, AS: {asn}"
                        logging.info(msg)
                        self.recent_correlation_findings.append(msg)
                        self.add_to_daily_buffer("geoips", msg)
                time.sleep(1.5)
            except Exception:
                pass

    def scan_leakix(self):
        logging.info("[Phase 1.5] Scanning LeakIX...")
        api_key = self.config.get("osint_apis", {}).get("leakix_api_key")
        if not api_key: return
        queries = ["titanium TargetCorp", "nova TargetCorp", "rudolph TargetCorp"]
        headers = {"api-key": api_key, "Accept": "application/json"}
        for q in queries:
            try:
                url = f"https://leakix.net/search?q={requests.utils.quote(q)}"
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list) and len(data) > 0:
                        msg = f"[LeakIX] Found {len(data)} results for query '{q}'"
                        logging.info(msg)
                        self.recent_correlation_findings.append(msg)
                        self.add_to_daily_buffer("mentions", msg)
            except Exception:
                pass

    def scan_private_ip_exposure(self, ips):
        logging.info("[Phase 1.5] Scanning for exposed Private IPs...")
        censys_token = self.config.get("osint_apis", {}).get("censys_token")
        shodan_key = self.config.get("osint_apis", {}).get("shodan_api_key")
        censys_headers = {"Authorization": f"Bearer {censys_token}", "Accept": "application/json"} if censys_token else None
        
        import time
        for ip in ips:
            if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
                continue
                
            exposed = False
            details = []
            
            # Check Censys
            if censys_headers:
                try:
                    url = f"https://search.censys.io/api/v2/hosts/{ip}"
                    response = requests.get(url, headers=censys_headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("result"):
                            exposed = True
                            services = data.get("result", {}).get("services", [])
                            details.append(f"Censys ({len(services)} services)")
                except Exception:
                    pass
                time.sleep(1.5)

            # Check Shodan
            if shodan_key:
                try:
                    url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        exposed = True
                        ports = data.get("ports", [])
                        details.append(f"Shodan (ports: {ports})")
                except Exception:
                    pass
                time.sleep(1.5)

            if exposed:
                msg = f"⚠️ IP PRIVADA EXPUESTA: {ip} indexada en {', '.join(details)}"
                logging.critical(msg)
                self.recent_correlation_findings.append(msg)
                # This automatically triggers write_alert because 0.90 > 0.70
                self.add_finding(f"exposed://{ip}", f"IP Privada Expuesta ({ip})", "OSINT Correlation", 0.90)
                self.add_to_daily_buffer("private_ips", msg)

    def scan_deep_web(self):
        logging.info("[Phase 4] Performing Deep Web OSINT (via Ahmia)...")
        for source in self.config.get("sources", []):
            if source["type"] == "ahmia_api":
                for query in source.get("queries", []):
                    try:
                        url = f"https://ahmia.fi/search/?q={requests.utils.quote(query)}"
                        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            results = soup.find_all('li', class_='result')
                            for res in results[:5]: # Top 5
                                title_elem = res.find('h4')
                                link_elem = res.find('cite')
                                if title_elem and link_elem:
                                    title = f"Onion Match: {title_elem.text.strip()}"
                                    link = f"onion://{link_elem.text.strip()}"
                                    self.add_finding(link, title, "Ahmia Deep Web", title + query)
                    except Exception as e:
                        logging.error(f"Error querying Ahmia for {query}: {e}")

    def active_probing(self, endpoints):
        logging.warning("[Phase 3] Initiating Active Probing (HEAD requests)...")
        for target in endpoints:
            url = f"https://{target}"
            try:
                # Use a rotating proxy if configured, otherwise direct
                # Simulate proxy rotation for this script
                proxies = {} # E.g., {"https": "http://proxy.example.com:8080"}
                
                # Conservative action: HEAD request only
                response = requests.head(url, timeout=5, proxies=proxies)
                status = response.status_code
                server = response.headers.get("Server", "Unknown")
                msg = f"HEAD Request to {url} returned {status} (Server: {server})"
                logging.info(msg)
                
                if status not in [404, 502, 503]:
                    self.add_finding(url, f"Active Endpoint Responded: {status}", "Active Probing", msg)
            except requests.exceptions.RequestException as e:
                logging.debug(f"Probing {url} failed: {e}")

    def scan_threat_intel(self, subdomains):
        logging.info("[Phase 1.5] Scanning Threat Intelligence APIs for new subdomains...")
        ti_config = self.config.get("threat_intel_apis", {})
        vt_key = ti_config.get("virustotal_key", "")
        st_key = ti_config.get("securitytrails_key", "")
        enable_otx = ti_config.get("enable_otx", True)
        enable_urlscan = ti_config.get("enable_urlscan", True)

        for domain in subdomains:
            if not self.is_new_item(domain, "threat_intel"):
                continue

            logging.info(f"Querying Threat Intel for {domain}...")
            
            # VirusTotal
            if vt_key:
                try:
                    headers = {"x-apikey": vt_key}
                    resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=10)
                    if resp.status_code == 200:
                        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        if malicious > 0:
                            msg = f"VirusTotal detection: {malicious} engines flagged {domain} as malicious."
                            self.add_to_daily_buffer("Inteligencias de Amenazas", msg)
                            self.alert_critical(domain, msg)
                    time.sleep(15) # Rate limit VT free
                except Exception as e:
                    logging.debug(f"VT Error for {domain}: {e}")

            # OTX
            if enable_otx:
                try:
                    resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general", timeout=10)
                    if resp.status_code == 200:
                        pulses = resp.json().get("pulse_info", {}).get("count", 0)
                        if pulses > 0:
                            msg = f"AlienVault OTX: {domain} is present in {pulses} pulses."
                            self.add_to_daily_buffer("Inteligencias de Amenazas", msg)
                            self.alert_critical(domain, msg)
                    time.sleep(1.5)
                except Exception as e:
                    logging.debug(f"OTX Error for {domain}: {e}")

            # URLScan
            if enable_urlscan:
                try:
                    resp = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=10)
                    if resp.status_code == 200:
                        results = resp.json().get("results", [])
                        if results:
                            msg = f"URLScan: {domain} has been scanned {len(results)} times."
                            self.add_to_daily_buffer("Inteligencias de Amenazas", msg)
                    time.sleep(2)
                except Exception as e:
                    logging.debug(f"URLScan Error for {domain}: {e}")

            # SecurityTrails
            if st_key:
                try:
                    headers = {"APIKEY": st_key, "accept": "application/json"}
                    resp = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true", headers=headers, timeout=10)
                    if resp.status_code == 200:
                        subs = resp.json().get("subdomains", [])
                        if subs:
                            msg = f"SecurityTrails: Found {len(subs)} historical subdomains for {domain}."
                            self.add_to_daily_buffer("Inteligencias de Amenazas", msg)
                    time.sleep(2)
                except Exception as e:
                    logging.debug(f"SecurityTrails Error for {domain}: {e}")

    def run_cycle(self):
        logging.info("Starting intelligence scan cycle...")
        
        phases = self.config.get("phases", {})
        
        if phases.get("phase1_osint", True):
            self.scan_rss()
            self.scan_github()
            self.scan_telegram()
            # crt.sh is called inside discover_dns if use_crtsh_data is true
            
        resolved_data = []
        if phases.get("phase2_dns_discovery", False):
            resolved_data = self.discover_dns()
            
        # Extract domains and IPs
        resolved_domains = [item["domain"] for item in resolved_data]
        all_ips = []
        for item in resolved_data:
            all_ips.extend(item["ips"])
        
        # Extract Codenames
        if resolved_domains:
            self.extract_codenames(resolved_domains)
        
        # Execute Phase 1.5 Correlation
        self.scan_wayback(resolved_domains)
        self.scan_shodan(all_ips)
        self.geolocate_ips(all_ips)
        self.scan_private_ip_exposure(all_ips)
        self.scan_leakix()
        self.scan_threat_intel(resolved_domains)

        if phases.get("phase4_deep_web", False):
            self.scan_deep_web()

        if phases.get("phase3_active_probing", False):
            if resolved_domains:
                self.active_probing(resolved_domains)
            else:
                logging.info("[Phase 3] No endpoints discovered in Phase 2 to probe.")
                
        # Daily Tasks
        today = datetime.now().strftime("%Y-%m-%d")
        last_run_file = "last_daily_run.txt"
        last_run = ""
        if os.path.exists(last_run_file):
            with open(last_run_file, "r") as f:
                last_run = f.read().strip()
                
        if last_run != today:
            self.generate_wordlists()
            self.generate_daily_summary()
            self.generate_correlation_report()
            with open(last_run_file, "w") as f:
                f.write(today)
            
        self.cleanup_reports()

    def generate_wordlists(self):
        logging.info("Generating daily wordlists...")
        try:
            with open("internal_codenames.txt", "r", encoding="utf-8") as f:
                codenames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            codenames = []

        static_terms = ["projectx", "targetmodel", "claude-4", "claude-next", "prometheus", "echo", "shadow", "iris", "chronos", "hermes", "athena", "gaia", "hades"]
        custom_wordlist = set(static_terms)
        subdomain_guesses = set()

        for code in codenames:
            custom_wordlist.update([
                code, f"{code}-api", f"{code}-staging", f"{code}-preview",
                f"{code}-internal", f"{code}-prod", f"{code}-projectx",
                f"{code}-targetmodel", f"{code}-v1", f"{code}-v2",
                f"claude-{code}", f"{code}.targetcorp.com"
            ])
            subdomain_guesses.update([
                f"{code}.api", f"{code}-staging.api", f"{code}.internal",
                f"sandbox-{code}", f"{code}-proxy", f"mcp-{code}"
            ])

        with open("custom_wordlist.txt", "w", encoding="utf-8") as f:
            for w in sorted(custom_wordlist): f.write(w + "\n")
        with open("subdomain_guesses.txt", "w", encoding="utf-8") as f:
            for s in sorted(subdomain_guesses): f.write(s + "\n")

    def generate_daily_summary(self):
        logging.info("Generating daily executive summary...")
        import json
        buffer_file = "daily_buffer.json"
        try:
            with open(buffer_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
            
        lines = ["# Daily Executive Summary\n"]
        has_content = False
        
        categories = [
            ("subdomains", "Nuevos Subdominios"),
            ("geoips", "Nuevas IPs Públicas y Geolocalización"),
            ("private_ips", "IPs Privadas Expuestas"),
            ("wayback", "URLs Históricas (Wayback)"),
            ("mentions", "Menciones OSINT (LeakIX/Ahmia)"),
            ("alerts", "Alertas Críticas (>0.7)")
        ]
        
        for cat, title in categories:
            items = data.get(cat, [])
            if items:
                has_content = True
                lines.append(f"**{title}**")
                for item in items[:5]: # Max 5 items per category to keep it brief
                    lines.append(f"- {item}")
                if len(items) > 5:
                    lines.append(f"- ... y {len(items)-5} más.")
                lines.append("")
                
        if not has_content:
            lines.append("Sin novedades en las últimas 24 horas.\n")
            
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logging.info(f"Daily summary generated: {summary_file}")
        
        if os.path.exists(buffer_file):
            os.remove(buffer_file)

    def generate_correlation_report(self):
        logging.info("Generando reporte de correlación y patrones...")
        report_path = "access_vectors_hypothesis.md"
        lines = ["# Hipótesis de Vectores de Acceso y Correlación OSINT\n\n"]
        lines.append(f"*Generado automáticamente el {datetime.now().strftime('%Y-%m-%d')}*\n\n")

        # 1. Servicios internos expuestos en cabeceras históricas (Wayback)
        lines.append("## 1. Detección de IPs Privadas en Cabeceras Históricas\n")
        private_ip_pattern = re.compile(r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)')
        found_private_ips = False
        try:
            with open("historic_endpoints.txt", "r") as f:
                for line in f:
                    if private_ip_pattern.search(line):
                        lines.append(f"- Posible filtración: `{line.strip()}`")
                        found_private_ips = True
        except Exception:
            pass
            
        if not found_private_ips:
            lines.append("- No se detectaron IPs privadas en el registro histórico actual.\n")
        lines.append("\n")

        # 2. Análisis de evolución (Wayback)
        lines.append("## 2. Evolución Histórica de Infraestructura (Wayback)\n")
        try:
            with open("daily_summary.md", "r", encoding="utf-8") as f:
                content = f.read()
                if "**URLs Históricas (Wayback)**" in content:
                    wayback_section = content.split("**URLs Históricas (Wayback)**")[1].split("**")[0]
                    lines.append(wayback_section.strip() + "\n")
                else:
                    lines.append("- Sin datos históricos recientes.\n")
        except Exception:
            lines.append("- No se pudo leer el resumen diario.\n")
        lines.append("\n")

        # 3. Correlación de nombres internos con rutas de API
        lines.append("## 3. Prioridad de Prueba: Conjeturas de Rutas API\n")
        codenames = []
        try:
            with open("internal_codenames.txt", "r", encoding="utf-8") as f:
                codenames = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
            
        if codenames:
            priority = ["projectx", "targetmodel", "nova", "titanium"]
            sorted_codes = sorted(codenames, key=lambda x: priority.index(x) if x in priority else 99)
            
            lines.append("Las siguientes rutas han sido generadas pasivamente y ordenadas por relevancia estratégica para fuzzing manual:\n")
            for code in sorted_codes[:15]:
                lines.append(f"- `https://api.targetcorp.com/v1/{code}`")
                lines.append(f"- `https://{code}.targetcorp.com/api`")
                lines.append(f"- `https://platform.claude.com/internal/{code}`")
        else:
            lines.append("- No hay nombres en código disponibles.\n")
        lines.append("\n")

        # 4. Diagrama Textual de Infraestructura
        lines.append("## 4. Mapa Jerárquico de Proveedores de Nube (GeoIP)\n")
        lines.append("```text")
        providers = {}
        try:
            with open("daily_summary.md", "r", encoding="utf-8") as f:
                for line in f:
                    if "[GeoIP]" in line:
                        org_match = re.search(r'organización:\s*([^,]+)', line)
                        ip_match = re.search(r'IP pública\s*([\d\.]+)', line)
                        if org_match and ip_match:
                            org = org_match.group(1).strip()
                            ip = ip_match.group(1).strip()
                            if org not in providers:
                                providers[org] = []
                            providers[org].append(ip)
        except Exception:
            pass

        if providers:
            for org, ips in providers.items():
                lines.append(f"[{org}]")
                for i, ip in enumerate(ips[:10]):
                    prefix = "└─" if i == len(ips[:10])-1 else "├─"
                    lines.append(f"{prefix} {ip}")
        else:
            lines.append("[No se encontraron datos de proveedores en el último reporte]")
        lines.append("```\n")
        
        # 5. Cambios recientes (7 días)
        lines.append("## 5. Cambios Críticos Recientes (Últimos 7 días)\n")
        try:
            cursor = self.conn.cursor()
            seven_days_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("SELECT title, timestamp FROM findings WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 5", (seven_days_ago,))
            recent = cursor.fetchall()
            if recent:
                for r in recent:
                    lines.append(f"- [{r[1]}] {r[0]}")
            else:
                lines.append("- No hay hallazgos críticos en la base de datos en los últimos 7 días.\n")
        except Exception as e:
            lines.append(f"- Error leyendo BD: {e}\n")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logging.info(f"Reporte de correlación generado en {report_path}")

    def cleanup_reports(self):
        logging.info("Cleaning up old reports (>30 days)...")
        cutoff = datetime.now() - timedelta(days=30)
        report_dir = self.config["report_dir"]
        try:
            for filename in os.listdir(report_dir):
                filepath = os.path.join(report_dir, filename)
                if os.path.isfile(filepath):
                    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_time < cutoff:
                        os.remove(filepath)
                        logging.info(f"Deleted old report: {filename}")
        except Exception as e:
            logging.error(f"Error cleaning up reports: {e}")

    def generate_report(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.config["report_dir"], filename)

        cursor = self.conn.cursor()
        cursor.execute("SELECT url, title, source, timestamp, confidence FROM findings ORDER BY confidence DESC, timestamp DESC LIMIT 10")
        findings = cursor.fetchall()

        with open(filepath, "w") as f:
            f.write(f"# projectx Intelligence V2 Report - [{timestamp}]\n\n")
            f.write("## High-Signal Intelligence\n")
            if not findings:
                f.write("- No high-confidence findings in this cycle.\n")
            for url, title, source, ts, conf in findings:
                f.write(f"### {title} (Confidence: {conf:.2f})\n")
                f.write(f"- Source: {source}\n")
                f.write(f"- Link: {url}\n")
                f.write(f"- Detected: {ts}\n\n")

            if self.recent_dns_resolutions:
                f.write("## DNS Resolutions (Phase 2)\n")
                for res in self.recent_dns_resolutions:
                    f.write(f"- **{res['target']}** resolved to:\n")
                    for ip in res['ips']:
                        f.write(f"  - {ip}\n")
                f.write("\n")
                self.recent_dns_resolutions = [] # clear after reporting
                
            if self.recent_correlation_findings:
                f.write("## Hallazgos Históricos y de Correlación (Fase 1.5)\n")
                for finding in self.recent_correlation_findings:
                    f.write(f"- {finding}\n")
                f.write("\n")
                self.recent_correlation_findings = []
        
        logging.info(f"Report generated: {filepath}")
        return filepath

    def start_loop(self):
        logging.info("projectx Intelligence V2 Loop active.")
        try:
            while True:
                self.run_cycle()
                self.generate_report()
                time.sleep(self.config["scan_interval_minutes"] * 60)
        except KeyboardInterrupt:
            logging.info("Loop suspended.")

if __name__ == "__main__":
    monitor = projectxMonitorV2()
    # Run once for the demo/seed
    monitor.run_cycle()
    monitor.generate_report()
