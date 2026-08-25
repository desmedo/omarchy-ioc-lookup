#!/usr/bin/env python3
"""
IOC Live Enrichment, Threat Intelligence & CLI Backend
Part of the Omarchy IOCs Lookup Shell Suite
"""

import sys
import json
import socket
import urllib.request
import urllib.parse
import os
import re
import ipaddress
import subprocess
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor

CONFIG_PATH  = os.path.expanduser("~/.config/omarchy/ioc-lookup.json")
HISTORY_PATH = os.path.expanduser("~/.local/state/omarchy/ioc-history.json")

# Per-provider concurrency caps (applied across all batch workers simultaneously).
# These prevent hammering rate-limited APIs when scanning large IOC batches.
#   ip-api.com   free tier: 45 req/min  → max 2 simultaneous
#   AbuseIPDB    free tier: 1000/day    → max 2 simultaneous
#   VirusTotal   free tier: 4 req/min   → max 1 simultaneous (sequential)
#   GreyNoise    community: ~1 req/s    → max 1 simultaneous
#   Cloudflare   DNS-over-HTTPS: generous → max 6 simultaneous
#   RDAP/NVD     public APIs            → max 3 simultaneous
_SEM_GEOIP    = threading.Semaphore(2)
_SEM_ABUSE    = threading.Semaphore(2)
_SEM_VT       = threading.Semaphore(1)
_SEM_GREY     = threading.Semaphore(1)
_SEM_DNS      = threading.Semaphore(6)
_SEM_RDAP     = threading.Semaphore(3)
_SEM_NVD      = threading.Semaphore(2)


def load_config():
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def load_history():
    if os.path.isfile(HISTORY_PATH):
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history_entry(entry):
    try:
        os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
        hist = load_history()
        hist = [h for h in hist if h.get("query", "").lower() != entry.get("query", "").lower()]
        hist.insert(0, entry)
        hist = hist[:100]
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(hist, f, indent=2)
    except Exception:
        pass

def fetch_json(url, headers=None, timeout=2.5):
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "OmarchyIOC/1.0"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        return {"_error": str(e)}

# ------------------------------------------------------------- Defang / Refang
def refang_text(s):
    if not s:
        return ""
    s = re.sub(r'h[xX]{2}ps://', 'https://', s, flags=re.IGNORECASE)
    s = re.sub(r'h[xX]{2}p://', 'http://', s, flags=re.IGNORECASE)
    s = re.sub(r'f[xX]{2}p://', 'ftp://', s, flags=re.IGNORECASE)
    s = re.sub(r'\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|\\.', '.', s, flags=re.IGNORECASE)
    s = re.sub(r'\[\:\]|\(\:\)|\{\:\}|\[colon\]', ':', s, flags=re.IGNORECASE)
    s = re.sub(r'\[\@\]|\(\@\)|\{\@\}|\[at\]', '@', s, flags=re.IGNORECASE)
    s = re.sub(r'\[\/\]|\(\/\)|\[slash\]', '/', s, flags=re.IGNORECASE)
    return s.strip()

def defang_text(s):
    if not s:
        return ""
    r = refang_text(s)
    r = re.sub(r'https://', 'hxxps://', r, flags=re.IGNORECASE)
    r = re.sub(r'http://', 'hxxp://', r, flags=re.IGNORECASE)
    r = re.sub(r'ftp://', 'fxxp://', r, flags=re.IGNORECASE)
    r = r.replace('.', '[.]')
    r = r.replace('@', '[@]')
    return r

def classify_ioc(val):
    val = val.strip().strip('"\'`<>[]()')
    ref = refang_text(val)
    
    try:
        ip = ipaddress.ip_address(ref)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4", ref
        elif isinstance(ip, ipaddress.IPv6Address):
            return "ipv6", ref
    except ValueError:
        pass

    if re.match(r'^CVE-\d{4}-\d{4,7}$', ref, re.IGNORECASE):
        return "cve", ref.upper()
    if re.match(r'^[a-f0-9]{64}$', ref, re.IGNORECASE):
        return "sha256", ref.lower()
    if re.match(r'^[a-f0-9]{40}$', ref, re.IGNORECASE):
        return "sha1", ref.lower()
    if re.match(r'^[a-f0-9]{32}$', ref, re.IGNORECASE):
        return "md5", ref.lower()
    if re.match(r'^(https?|ftp)://', ref, re.IGNORECASE):
        return "url", ref
    if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$', ref):
        return "domain", ref.lower()
    if re.match(r'^AS\d{1,10}$', ref, re.IGNORECASE):
        return "asn", ref.upper()
    
    return "text", ref

def extract_all_iocs(text):
    seen = set()
    results = []

    def add(t, v):
        k = f"{t}:{v.lower()}"
        if k not in seen:
            seen.add(k)
            results.append({"type": t, "refanged": v, "defanged": defang_text(v)})

    # URLs
    for u in re.findall(r'(?:https?|hxxps?|ftp|fxxp)://[^\s<>"\'`()\[\]]+', text, re.IGNORECASE):
        add("url", refang_text(u))
    # CVEs
    for c in re.findall(r'\bCVE-\d{4}-\d{4,7}\b', text, re.IGNORECASE):
        add("cve", c.upper())
    # Hashes
    for h in re.findall(r'\b[a-f0-9]{64}\b', text, re.IGNORECASE):
        add("sha256", h.lower())
    for h in re.findall(r'\b[a-f0-9]{40}\b', text, re.IGNORECASE):
        add("sha1", h.lower())
    for h in re.findall(r'\b[a-f0-9]{32}\b', text, re.IGNORECASE):
        add("md5", h.lower())
    # IPs
    for ip in re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.\[\]()]{1,3}){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text):
        clean_ip = refang_text(ip)
        try:
            ipaddress.IPv4Address(clean_ip)
            add("ipv4", clean_ip)
        except ValueError:
            pass
    # Domains
    for d in re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?[.\[\]()]{1,3})+[a-zA-Z]{2,63}\b', text):
        clean_d = refang_text(d)
        if not re.search(r'\.(?:png|jpg|jpeg|gif|svg|webp|qml|js|json|toml|lua|conf|txt|log|py|sh|c|h|cpp|go|rs|css|html|md)$', clean_d, re.IGNORECASE):
            add("domain", clean_d.lower())

    return results

# ------------------------------------------------------------- Lookups
def lookup_ip(ip, config):
    result = {
        "status": "success",
        "type": "ip",
        "query": ip,
        "is_private": False
    }

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
            result["is_private"] = True
            result["note"] = "Private / RFC1918 / Loopback address"
            result["country"] = "Local / Private"
            result["city"] = "LAN / Loopback"
            result["isp"] = "Internal Network"
            return result
    except ValueError:
        pass

    def get_ptr():
        try:
            socket.setdefaulttimeout(1.5)
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return ""

    def get_geoip():
        with _SEM_GEOIP:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
            return fetch_json(url, timeout=2.5)

    def get_abuseipdb():
        key = config.get("abuseipdb_api_key")
        if not key:
            return None
        with _SEM_ABUSE:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose=false"
            return fetch_json(url, headers={"Key": key, "Accept": "application/json"}, timeout=2.5)

    def get_virustotal_ip():
        key = config.get("virustotal_api_key")
        if not key:
            return None
        with _SEM_VT:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}"
            return fetch_json(url, headers={"x-apikey": key}, timeout=3.0)

    def get_greynoise():
        with _SEM_GREY:
            key = config.get("greynoise_api_key")
            if key:
                url = f"https://api.greynoise.io/v2/noise/quick/{urllib.parse.quote(ip)}"
                return fetch_json(url, headers={"key": key}, timeout=2.5)
            # Community endpoint — no key required, ~1 req/s
            url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}"
            return fetch_json(url, timeout=2.5)

    with ThreadPoolExecutor(max_workers=5) as executor:
        f_ptr   = executor.submit(get_ptr)
        f_geo   = executor.submit(get_geoip)
        f_abuse = executor.submit(get_abuseipdb)
        f_vt    = executor.submit(get_virustotal_ip)
        f_gn    = executor.submit(get_greynoise)

        ptr   = f_ptr.result()
        geo   = f_geo.result()
        abuse = f_abuse.result()
        vt    = f_vt.result()
        gn    = f_gn.result()

    if geo and geo.get("status") == "success":
        result.update({
            "country": geo.get("country", ""),
            "countryCode": geo.get("countryCode", ""),
            "city": geo.get("city", ""),
            "region": geo.get("regionName", ""),
            "isp": geo.get("isp", ""),
            "org": geo.get("org", ""),
            "as": geo.get("as", ""),
            "asname": geo.get("asname", ""),
            "ptr": ptr or geo.get("reverse", "")
        })
    else:
        result["ptr"] = ptr
        result["country"] = "Unknown"
        result["isp"] = "Unknown"

    if abuse and "data" in abuse:
        d = abuse["data"]
        result["abuse_score"]   = d.get("abuseConfidenceScore", 0)
        result["total_reports"] = d.get("totalReports", 0)
        result["usage_type"]    = d.get("usageType", "")

    if vt and "data" in vt:
        attrs = vt["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["vt_malicious"]  = stats.get("malicious", 0)
        result["vt_suspicious"] = stats.get("suspicious", 0)
        result["vt_harmless"]   = stats.get("harmless", 0)
        result["vt_undetected"] = stats.get("undetected", 0)
        engines = attrs.get("last_analysis_results", {})
        result["vt_flagged_by"] = [n for n, r in engines.items() if r.get("category") == "malicious"][:5]

    if gn and "_error" not in gn:
        result["greynoise_noise"]           = gn.get("noise", False)
        result["greynoise_riot"]            = gn.get("riot", False)
        result["greynoise_classification"]  = gn.get("classification", "")
        result["greynoise_name"]            = gn.get("name", "")
        result["greynoise_message"]         = gn.get("message", "")

    summary = f"{result.get('country', '')} • {result.get('isp', '')}"
    if result.get("as"):
        summary += f" ({result['as']})"
    if "abuse_score" in result:
        summary += f" • Abuse: {result['abuse_score']}%"
    if result.get("vt_malicious"):
        summary += f" • VT: {result['vt_malicious']} detections"
    if result.get("greynoise_noise"):
        summary += f" • GreyNoise: {result.get('greynoise_classification', 'noise')}"

    save_history_entry({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": ip,
        "refanged": ip,
        "defanged": defang_text(ip),
        "type": "IPv4",
        "summary": summary
    })

    return result

def lookup_domain(domain, config):
    result = {
        "status": "success",
        "type": "domain",
        "query": domain,
        "ips": [],
        "ipv6": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "registrar": "",
        "created": "",
        "expires": ""
    }

    def get_dns_a():
        with _SEM_DNS:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=A"
            res = fetch_json(url, headers={"Accept": "application/dns-json"}, timeout=2.0)
            if res and "Answer" in res:
                return [a["data"] for a in res["Answer"] if a.get("type") == 1]
            return []

    def get_dns_aaaa():
        with _SEM_DNS:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=AAAA"
            res = fetch_json(url, headers={"Accept": "application/dns-json"}, timeout=2.0)
            if res and "Answer" in res:
                return [a["data"] for a in res["Answer"] if a.get("type") == 28]
            return []

    def get_dns_mx():
        with _SEM_DNS:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=MX"
            res = fetch_json(url, headers={"Accept": "application/dns-json"}, timeout=2.0)
            if res and "Answer" in res:
                return [a["data"] for a in res["Answer"] if a.get("type") == 15]
            return []

    def get_dns_ns():
        with _SEM_DNS:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=NS"
            res = fetch_json(url, headers={"Accept": "application/dns-json"}, timeout=2.0)
            if res and "Answer" in res:
                return [a["data"] for a in res["Answer"] if a.get("type") == 2]
            return []

    def get_dns_txt():
        with _SEM_DNS:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=TXT"
            res = fetch_json(url, headers={"Accept": "application/dns-json"}, timeout=2.0)
            if res and "Answer" in res:
                return [a["data"].strip('"') for a in res["Answer"] if a.get("type") == 16][:3]
            return []

    def get_rdap():
        with _SEM_RDAP:
            url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
            return fetch_json(url, headers={"Accept": "application/json"}, timeout=2.5)

    def get_virustotal_domain():
        key = config.get("virustotal_api_key")
        if not key:
            return None
        with _SEM_VT:
            url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
            return fetch_json(url, headers={"x-apikey": key}, timeout=3.0)

    with ThreadPoolExecutor(max_workers=7) as executor:
        f_a    = executor.submit(get_dns_a)
        f_aaaa = executor.submit(get_dns_aaaa)
        f_mx   = executor.submit(get_dns_mx)
        f_ns   = executor.submit(get_dns_ns)
        f_txt  = executor.submit(get_dns_txt)
        f_rdap = executor.submit(get_rdap)
        f_vt   = executor.submit(get_virustotal_domain)

        result["ips"]  = f_a.result()
        result["ipv6"] = f_aaaa.result()
        result["mx"]   = f_mx.result()
        result["ns"]   = f_ns.result()
        result["txt"]  = f_txt.result()
        rdap = f_rdap.result()
        vt   = f_vt.result()

    if rdap and "_error" not in rdap:
        entities = rdap.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1:
                    for prop in vcard[1]:
                        if prop and prop[0] == "fn":
                            result["registrar"] = prop[3]
                            break
        events = rdap.get("events", [])
        for ev in events:
            action = ev.get("eventAction")
            date_val = ev.get("eventDate", "")[:10]
            if action == "registration":
                result["created"] = date_val
            elif action == "expiration":
                result["expires"] = date_val

    if vt and "data" in vt:
        attrs = vt["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result["vt_malicious"]  = stats.get("malicious", 0)
        result["vt_suspicious"] = stats.get("suspicious", 0)
        result["vt_harmless"]   = stats.get("harmless", 0)
        result["vt_undetected"] = stats.get("undetected", 0)
        result["vt_reputation"] = attrs.get("reputation", None)
        result["vt_categories"] = list(attrs.get("categories", {}).values())[:3]
        engines = attrs.get("last_analysis_results", {})
        result["vt_flagged_by"] = [n for n, r in engines.items() if r.get("category") == "malicious"][:5]

    summary = ""
    if result["ips"]:
        summary += f"IPs: {', '.join(result['ips'][:3])}"
    if result.get("registrar"):
        summary += f" • Registrar: {result['registrar']}"
    if result.get("vt_malicious"):
        summary += f" • VT: {result['vt_malicious']} detections"
    save_history_entry({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": domain,
        "refanged": domain,
        "defanged": defang_text(domain),
        "type": "Domain",
        "summary": summary or "Resolved domain"
    })

    return result

def lookup_url(url_val, config):
    parsed = urllib.parse.urlparse(url_val if "://" in url_val else f"http://{url_val}")
    hostname = parsed.hostname or ""
    dom_result = lookup_domain(hostname, config) if hostname else {}
    
    save_history_entry({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": url_val,
        "refanged": url_val,
        "defanged": defang_text(url_val),
        "type": "URL",
        "summary": f"Host: {hostname} • Path: {parsed.path or '/'}"
    })

    return {
        "status": "success",
        "type": "url",
        "query": url_val,
        "scheme": parsed.scheme,
        "host": hostname,
        "path": parsed.path or "/",
        "query_string": parsed.query,
        "ips": dom_result.get("ips", []),
        "registrar": dom_result.get("registrar", "")
    }

def lookup_cve(cve_id, config):
    cve_upper = cve_id.upper()
    result = {
        "status": "success",
        "type": "cve",
        "query": cve_upper,
        "score": None,
        "severity": "UNKNOWN",
        "vector": "",
        "published": "",
        "description": ""
    }

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_upper)}"
    with _SEM_NVD:
        data = fetch_json(url, timeout=3.5)

    if data and "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
        cve_node = data["vulnerabilities"][0].get("cve", {})
        result["published"] = cve_node.get("published", "")[:10]
        
        descs = cve_node.get("descriptions", [])
        for d in descs:
            if d.get("lang") == "en":
                result["description"] = d.get("value", "")
                break
        if not result["description"] and descs:
            result["description"] = descs[0].get("value", "")

        metrics = cve_node.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_list:
            cdata = cvss_list[0].get("cvssData", {})
            result["score"]    = cdata.get("baseScore")
            result["severity"] = cdata.get("baseSeverity", "UNKNOWN").upper()
            result["vector"]   = cdata.get("vectorString", "")
            result["attack_vector"]       = cdata.get("attackVector", "")
            result["attack_complexity"]   = cdata.get("attackComplexity", "")
            result["privileges_required"] = cdata.get("privilegesRequired", "")
            result["user_interaction"]    = cdata.get("userInteraction", "")
            result["scope"]               = cdata.get("scope", "")
            result["confidentiality"]     = cdata.get("confidentialityImpact", "")
            result["integrity"]           = cdata.get("integrityImpact", "")
            result["availability"]        = cdata.get("availabilityImpact", "")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cdata = metrics["cvssMetricV2"][0].get("cvssData", {})
            result["score"]    = cdata.get("baseScore")
            result["severity"] = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN").upper()
            result["vector"]   = cdata.get("vectorString", "")

        # CWE weakness identifiers
        weaknesses = cve_node.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    cwes.append(d.get("value", ""))
        result["cwe"] = cwes[:3]

        # First 5 references
        result["references"] = [r.get("url", "") for r in cve_node.get("references", [])[:5]]

        # Affected product names from CPE
        configs = cve_node.get("configurations", [])
        products = set()
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) > 4:
                        products.add(f"{parts[3]} {parts[4]}")
        result["affected_products"] = sorted(products)[:8]
    else:
        result["description"] = f"No NVD vulnerability details found for {cve_upper}."

    save_history_entry({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": cve_upper,
        "refanged": cve_upper,
        "defanged": cve_upper,
        "type": "CVE",
        "summary": f"Score: {result.get('score', 'N/A')} {result.get('severity', '')} • {result.get('description', '')[:60]}..."
    })

    return result

def lookup_hash(hash_val, config):
    algo = "MD5" if len(hash_val) == 32 else ("SHA-1" if len(hash_val) == 40 else ("SHA-256" if len(hash_val) == 64 else "SHA-512"))
    result = {
        "status": "success",
        "type": "hash",
        "query": hash_val,
        "length": len(hash_val),
        "algorithm": algo
    }

    vt_key = config.get("virustotal_api_key")
    if vt_key:
        with _SEM_VT:
            url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
            vt_data = fetch_json(url, headers={"x-apikey": vt_key}, timeout=2.5)
        if vt_data and "data" in vt_data:
            attrs = vt_data["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["vt_malicious"]    = stats.get("malicious", 0)
            result["vt_suspicious"]   = stats.get("suspicious", 0)
            result["vt_harmless"]     = stats.get("harmless", 0)
            result["vt_undetected"]   = stats.get("undetected", 0)
            result["file_type"]       = attrs.get("type_description", "")
            result["meaningful_name"] = attrs.get("meaningful_name", "")
            result["file_size"]       = attrs.get("size")
            result["times_submitted"] = attrs.get("times_submitted", 0)
            result["known_names"]     = attrs.get("names", [])[:5]
            result["vt_link"]         = f"https://www.virustotal.com/gui/file/{hash_val}"
            # Top flagging engines (name + their detection label)
            engines = attrs.get("last_analysis_results", {})
            result["vt_detections"] = [
                {"engine": n, "result": r.get("result", "")}
                for n, r in engines.items()
                if r.get("category") == "malicious"
            ][:8]
            # Signature info if available (PE/ELF/Mach-O)
            sig = attrs.get("signature_info", {})
            if sig:
                result["signature_subject"]  = sig.get("subject", "")
                result["signature_verified"]  = sig.get("verified", "")

    total_scans = (result.get("vt_malicious", 0) + result.get("vt_harmless", 0) + result.get("vt_undetected", 0))
    summary = f"{algo} ({len(hash_val)} chars)"
    if "vt_malicious" in result:
        summary += f" • VT: {result['vt_malicious']}/{total_scans} detections"
        if result.get("meaningful_name"):
            summary += f" [{result['meaningful_name']}]"

    save_history_entry({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "query": hash_val,
        "refanged": hash_val,
        "defanged": hash_val,
        "type": algo,
        "summary": summary
    })

    return result

# ------------------------------------------------------------- Parallel Batch Lookup
def run_single_enrichment(item, config):
    t = item.get("type", "").lower()
    ref = item.get("refanged", item.get("value", ""))
    summary = ""
    details = {}

    try:
        if t in ("ipv4", "ipv6", "ip"):
            details = lookup_ip(ref, config)
            if details.get("is_private"):
                summary = "Private RFC1918 Address"
            else:
                summary = f"{details.get('country', 'Unknown')} • {details.get('isp', 'Unknown')}"
                if details.get("as"):
                    summary += f" ({details['as']})"
                if "abuse_score" in details:
                    summary += f" • Abuse: {details['abuse_score']}%"
                if details.get("vt_malicious"):
                    summary += f" • VT: {details['vt_malicious']} detections"
                if details.get("greynoise_noise"):
                    summary += f" • GreyNoise: {details.get('greynoise_classification', 'noise')}"
        elif t == "domain":
            details = lookup_domain(ref, config)
            if details.get("ips"):
                summary = f"IPs: {', '.join(details['ips'][:2])}"
            if details.get("registrar"):
                summary += f" • Registrar: {details['registrar']}"
            if details.get("vt_malicious"):
                summary += f" • VT: {details['vt_malicious']} detections"
        elif t == "cve":
            details = lookup_cve(ref, config)
            summary = f"Score: {details.get('score', 'N/A')} {details.get('severity', '')} • {details.get('description', '')[:50]}"
        elif t in ("md5", "sha1", "sha256", "sha512", "hash"):
            details = lookup_hash(ref, config)
            total = details.get("vt_malicious", 0) + details.get("vt_harmless", 0) + details.get("vt_undetected", 0)
            summary = f"{details.get('algorithm', 'Hash')} ({details.get('length', 0)} chars)"
            if "vt_malicious" in details:
                summary += f" • VT: {details['vt_malicious']}/{total} detections"
                if details.get("meaningful_name"):
                    summary += f" [{details['meaningful_name']}]"
        elif t == "url":
            details = lookup_url(ref, config)
            summary = f"Host: {details.get('host', '')} • Path: {details.get('path', '/')}"
            if details.get("vt_malicious"):
                summary += f" • VT: {details['vt_malicious']} detections"
        else:
            summary = "Indicator"
    except Exception as e:
        summary = f"Lookup error: {e}"

    res_item = dict(item)
    res_item["summary"] = summary or "Enriched"
    res_item["details"] = details
    return res_item

def batch_lookup_all(items_list, config):
    if not items_list:
        return []
    # Outer pool is intentionally small (4 workers). Each lookup spawns its own
    # inner thread pool; keeping the outer count low prevents a thread explosion
    # (e.g. 50 IOCs × 7 inner workers = 350 threads) and lets the module-level
    # per-API semaphores do their rate-limiting job effectively.
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_single_enrichment, item, config) for item in items_list]
        return [f.result() for f in futures]

# ------------------------------------------------------------- CLI Display
def print_cli_card(res, ioc_type, val):
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    RESET = "\033[0m"

    print(f"\n{BOLD}{CYAN}🛡️  Omarchy IOCs Lookup{RESET} {DIM}• Threat Intelligence & Enrichment{RESET}")
    print(f"{DIM}─────────────────────────────────────────────────────────────{RESET}")
    print(f" {BOLD}Query:{RESET}     {val}")
    print(f" {BOLD}Type:{RESET}      {GREEN}{ioc_type.upper()}{RESET}")
    print(f" {BOLD}Defanged:{RESET}  {YELLOW}{defang_text(val)}{RESET}")
    print(f" {BOLD}Refanged:{RESET}  {val}")
    print(f"{DIM}─────────────────────────────────────────────────────────────{RESET}")

    if ioc_type in ("ipv4", "ipv6", "ip"):
        if res.get("is_private"):
            print(f" {YELLOW}⚠️  Private RFC1918 / Loopback Address{RESET}")
        else:
            print(f" {BOLD}Location:{RESET}  {res.get('country', 'Unknown')} ({res.get('city', 'Unknown')})")
            print(f" {BOLD}ISP / AS:{RESET}  {res.get('isp', 'Unknown')} • {res.get('as', '')}")
            print(f" {BOLD}Reverse:{RESET}   {res.get('ptr', '(No PTR hostname)')}")
            if "abuse_score" in res:
                color = RED if res["abuse_score"] >= 50 else (YELLOW if res["abuse_score"] > 0 else GREEN)
                print(f" {BOLD}AbuseIPDB:{RESET} {color}{res['abuse_score']}% Confidence Score{RESET} ({res.get('total_reports', 0)} reports)")

    elif ioc_type == "domain":
        ips_str = ", ".join(res.get("ips", [])) or "(No A records)"
        print(f" {BOLD}Resolved:{RESET}  {ips_str}")
        print(f" {BOLD}Registrar:{RESET} {res.get('registrar', 'Unknown')}")
        print(f" {BOLD}Lifecycle:{RESET} Created: {res.get('created', '—')} • Expires: {res.get('expires', '—')}")

    elif ioc_type == "cve":
        score = res.get("score", "N/A")
        sev = res.get("severity", "UNKNOWN")
        color = RED if sev in ("CRITICAL", "HIGH") else (YELLOW if sev == "MEDIUM" else GREEN)
        print(f" {BOLD}CVSS Score:{RESET} {color}{score} {sev}{RESET}")
        print(f" {BOLD}Published:{RESET}  {res.get('published', '—')}")
        print(f" {BOLD}Vector:{RESET}     {res.get('vector', '—')}")
        print(f"\n {BOLD}Advisory Summary:{RESET}\n {res.get('description', '')}\n")

    elif ioc_type in ("md5", "sha1", "sha256", "sha512", "hash"):
        print(f" {BOLD}Algorithm:{RESET} {res.get('algorithm', '')} ({res.get('length', 0)} hex characters)")
        if "vt_malicious" in res:
            color = RED if res["vt_malicious"] > 0 else GREEN
            print(f" {BOLD}VirusTotal:{RESET} {color}{res['vt_malicious']} detections{RESET} ({res.get('file_type', '')})")

    print(f"{DIM}─────────────────────────────────────────────────────────────{RESET}")
    print(f" {BOLD}Portals:{RESET}")
    print(f" • VirusTotal:   https://www.virustotal.com/gui/search/{urllib.parse.quote(val)}")
    if ioc_type in ("ipv4", "ipv6", "ip"):
        print(f" • AbuseIPDB:    https://www.abuseipdb.com/check/{urllib.parse.quote(val)}")
        print(f" • Shodan:       https://www.shodan.io/host/{urllib.parse.quote(val)}")
    elif ioc_type == "domain":
        print(f" • URLScan:      https://urlscan.io/domain/{urllib.parse.quote(val)}")
    elif ioc_type == "cve":
        print(f" • NVD NIST:     https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(val)}")
    print(f"{DIM}─────────────────────────────────────────────────────────────{RESET}\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: lookup.py <type> <value>  OR  ioc <target>")
        sys.exit(1)

    config = load_config()
    arg1 = sys.argv[1]

    # Batch JSON lookup via stdin — payload is a single JSON line written by
    # QML's onStarted handler followed by \n. readline() returns immediately on
    # that newline without needing EOF, which QML never sends.
    if arg1 in ("--batch-stdin",):
        try:
            raw_json = sys.stdin.readline()
            items = json.loads(raw_json)
            enriched = batch_lookup_all(items, config)
            print(json.dumps(enriched))
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e)}))
        return

    if arg1 in ("--batch", "-b"):
        raw_json = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
        try:
            items = json.loads(raw_json)
            enriched = batch_lookup_all(items, config)
            print(json.dumps(enriched))
        except Exception as e:
            print(json.dumps({"status": "error", "message": str(e)}))
        return

    # CLI flags
    if arg1 in ("-d", "--defang"):
        target = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
        print(defang_text(target))
        return
    if arg1 in ("-r", "--refang"):
        target = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
        print(refang_text(target))
        return
    if arg1 in ("-e", "--extract"):
        target = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
        if os.path.isfile(target):
            with open(target, "r", encoding="utf-8") as f:
                target = f.read()
        extracted = extract_all_iocs(target)
        if "--auto" in sys.argv or "--lookup" in sys.argv:
            extracted = batch_lookup_all(extracted, config)

        if "--json" in sys.argv:
            print(json.dumps(extracted, indent=2))
        else:
            print(f"\nExtracted & Enriched {len(extracted)} Indicators of Compromise:\n")
            print(f"{'TYPE':<10} {'REFANGED':<30} {'SUMMARY'}")
            print("-" * 80)
            for item in extracted:
                sum_text = item.get("summary", item.get("defanged", ""))
                print(f"{item['type']:<10} {item['refanged']:<30} {sum_text}")
            print("")
        return
    if arg1 in ("--history", "-H"):
        hist = load_history()
        print(f"\nRecent IOC Investigations ({len(hist)} entries):\n")
        print(f"{'TIMESTAMP':<20} {'TYPE':<8} {'INDICATOR':<30} {'DETAILS'}")
        print("-" * 80)
        for h in hist[:20]:
            print(f"{h.get('timestamp',''):<20} {h.get('type',''):<8} {h.get('query',''):<30} {h.get('summary','')}")
        print("")
        return
    if arg1 in ("--export", "-E"):
        hist = load_history()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md = f"# IOC Investigation Report\n**Generated:** {now}  \n**Total Indicators:** {len(hist)}\n\n"
        md += "| Timestamp | Type | Indicator (Refanged) | Indicator (Defanged) | Summary |\n|---|---|---|---|---|\n"
        for h in hist:
            md += f"| {h.get('timestamp','')} | {h.get('type','')} | `{h.get('refanged', h.get('query',''))}` | `{h.get('defanged', '')}` | {h.get('summary','')} |\n"
        print(md)
        return

    # Single or Two-Arg invocation
    if len(sys.argv) == 2:
        ioc_type, ioc_val = classify_ioc(arg1)
        if ioc_type in ("ipv4", "ipv6"):
            res = lookup_ip(ioc_val, config)
        elif ioc_type == "domain":
            res = lookup_domain(ioc_val, config)
        elif ioc_type == "url":
            res = lookup_url(ioc_val, config)
        elif ioc_type == "cve":
            res = lookup_cve(ioc_val, config)
        elif ioc_type in ("md5", "sha1", "sha256", "sha512"):
            res = lookup_hash(ioc_val, config)
        else:
            res = {"status": "unknown", "type": ioc_type, "query": ioc_val}
        
        print_cli_card(res, ioc_type, ioc_val)
        return

    # Two args from Quickshell QML: lookup.py <type> <value>
    ioc_type = sys.argv[1].lower()
    ioc_val = sys.argv[2].strip()

    try:
        if ioc_type in ("ipv4", "ipv6", "ip"):
            res = lookup_ip(ioc_val, config)
        elif ioc_type == "domain":
            res = lookup_domain(ioc_val, config)
        elif ioc_type == "url":
            res = lookup_url(ioc_val, config)
        elif ioc_type == "cve":
            res = lookup_cve(ioc_val, config)
        elif ioc_type in ("md5", "sha1", "sha256", "sha512", "hash"):
            res = lookup_hash(ioc_val, config)
        else:
            res = {"status": "unknown", "type": ioc_type, "query": ioc_val}
        
        print(json.dumps(res))
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))

if __name__ == "__main__":
    main()
