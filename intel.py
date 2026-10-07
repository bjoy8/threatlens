"""ThreatLens 3.0 - passive / low-touch OSINT & threat-intel correlation engine.
Keys (env or .env): VT_API_KEY, ABUSEIPDB_KEY, ABUSECH_KEY (URLhaus + MalwareBazaar + ThreatFox)
Tuning: VT_RPM (default 4 = VirusTotal free tier), CACHE_TTL seconds (default 900)"""
import re, os, ssl, csv, io, json, math, time, uuid, base64, socket, random, string, hashlib, ipaddress, threading, datetime as dt
from collections import deque, Counter
from concurrent.futures import ThreadPoolExecutor as TP
from urllib.parse import urlparse, urljoin
import requests, dns.resolver, dns.reversename

VER = "3.0"
UA = {"User-Agent": f"Mozilla/5.0 (X11; Linux x86_64) ThreatLens/{VER}"}
SEV = {"info": 0, "low": 6, "medium": 18, "high": 40, "critical": 70}
KEYS = ("VT_API_KEY", "ABUSEIPDB_KEY", "ABUSECH_KEY")
BL = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.dronebl.org", "psbl.surriel.com"]
RISKY = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
         5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
EP = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
ABCAT = {1: "DNS compromise", 2: "DNS poisoning", 3: "Fraud orders", 4: "DDoS", 5: "FTP brute-force", 6: "Ping of death",
         7: "Phishing", 8: "Fraud VoIP", 9: "Open proxy", 10: "Web spam", 11: "Email spam", 12: "Blog spam", 13: "VPN IP",
         14: "Port scan", 15: "Hacking", 16: "SQL injection", 17: "Spoofing", 18: "Brute-force", 19: "Bad web bot",
         20: "Exploited host", 21: "Web app attack", 22: "SSH abuse", 23: "IoT targeted"}
SITES = {"GitHub": "https://github.com/{}", "GitLab": "https://gitlab.com/{}", "Bitbucket": "https://bitbucket.org/{}/",
         "Codeberg": "https://codeberg.org/{}", "Dev.to": "https://dev.to/{}", "Medium": "https://medium.com/@{}",
         "Keybase": "https://keybase.io/{}", "DockerHub": "https://hub.docker.com/u/{}", "PyPI": "https://pypi.org/user/{}/",
         "npm": "https://www.npmjs.com/~{}", "Reddit": "https://www.reddit.com/user/{}/", "HackerOne": "https://hackerone.com/{}",
         "Lichess": "https://lichess.org/@/{}", "Linktree": "https://linktr.ee/{}", "Pastebin": "https://pastebin.com/u/{}",
         "Wikipedia": "https://en.wikipedia.org/wiki/User:{}", "Gravatar": "https://en.gravatar.com/{}",
         "Mastodon": "https://mastodon.social/@{}", "Twitch": "https://www.twitch.tv/{}", "SoundCloud": "https://soundcloud.com/{}",
         "Steam": "https://steamcommunity.com/id/{}", "Replit": "https://replit.com/@{}", "Kaggle": "https://www.kaggle.com/{}",
         "Chess.com": "https://www.chess.com/member/{}", "Behance": "https://www.behance.net/{}", "About.me": "https://about.me/{}",
         "Telegram": "https://t.me/{}"}
BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "facebook", "instagram", "netflix", "linkedin", "github", "dropbox",
          "adobe", "whatsapp", "twitter", "coinbase", "binance", "metamask", "chase", "wellsfargo", "bankofamerica", "citibank",
          "hsbc", "fedex", "office365", "outlook", "icloud", "spotify", "docusign", "telegram", "walmart", "santander", "barclays"]
RISKY_TLD = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "zip", "mov", "click", "country", "kim", "work", "rest", "icu", "buzz", "cyou", "monster", "cam", "sbs"}
TAKE = ("github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com", "s3-website", "azurewebsites.net", "cloudapp.net",
        "trafficmanager.net", "blob.core.windows.net", "cloudfront.net", "fastly.net", "myshopify.com", "wordpress.com", "zendesk.com",
        "readme.io", "ghost.io", "surge.sh", "netlify.app", "pantheonsite.io", "bitbucket.io", "unbouncepages.com", "helpscoutdocs.com",
        "statuspage.io", "uservoice.com", "cargocollective.com", "tumblr.com", "webflow.io", "elasticbeanstalk.com")
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org", "yopmail.com", "trashmail.com",
              "sharklasers.com", "getnada.com", "dispostable.com", "maildrop.cc", "throwawaymail.com", "fakeinbox.com", "mintemail.com",
              "moakt.com", "burnermail.io", "tempmailo.com"}
RS = dns.resolver.Resolver(); RS.nameservers = ["1.1.1.1", "8.8.8.8"]; RS.lifetime = 4
NOW = lambda: dt.datetime.now(dt.timezone.utc)

# ---------------------------------------------------------------- HTTP layer: cache, retry, rate-limit, per-source status
TL, CL, CACHE, KEYED = threading.local(), threading.Lock(), {}, set()
TTL = int(os.getenv("CACHE_TTL", "900"))

class Limiter:  # sliding-window limiter; gives up (returns False) instead of stalling a scan forever
    def __init__(s, rpm, max_wait): s.rpm, s.mw, s.t, s.l = max(1, rpm), max_wait, deque(), threading.Lock()
    def acquire(s):
        end = time.monotonic() + s.mw
        while True:
            with s.l:
                n = time.monotonic()
                while s.t and n - s.t[0] > 60: s.t.popleft()
                if len(s.t) < s.rpm: s.t.append(n); return True
                wait = 60 - (n - s.t[0])
            if time.monotonic() + wait > end: return False
            time.sleep(wait + .05)
VTL = Limiter(int(os.getenv("VT_RPM", "4")), 25)

def _note(c):
    s = getattr(TL, "st", None)
    if s is not None: s.append(c)

def X(method, url, *, cache=True, lim=None, tries=2, fmt="json", **kw):
    hd, to = {**UA, **kw.pop("headers", {})}, kw.pop("timeout", 8)
    ck = repr((method, url, fmt, sorted(kw.items(), key=lambda i: i[0])))  # API keys live in headers -> never in the cache key
    if cache:
        with CL: h = CACHE.get(ck)
        if h and time.time() - h[0] < TTL: _note(200); return h[1]
    for i in range(tries):
        if lim and not lim.acquire(): _note(429); return None
        try: r = requests.request(method, url, headers=hd, timeout=to, **kw)
        except requests.RequestException: _note("exc"); time.sleep(.4 * (i + 1)); continue
        _note(r.status_code)
        if r.status_code >= 500: time.sleep(.8 * (i + 1)); continue
        if not r.ok: return None
        try: out = r.json() if fmt == "json" else r.text
        except ValueError: return None
        if cache:
            with CL:
                if len(CACHE) > 2000: CACHE.clear()
                CACHE[ck] = (time.time(), out)
        return out
    return None
G = lambda url, **kw: X("GET", url, **kw)

def run(S, name, fn, *a, key=None, **kw):
    """Run one collector and record how it went: ok / no_data / no_key / auth_failed / rate_limited / unreachable."""
    if key: KEYED.add(name)
    if key and not os.getenv(key): S.setdefault(name, "no_key"); return None
    TL.st = []
    try: out = fn(*a, **kw)
    except Exception: out = None; TL.st.append("exc")
    st = set(TL.st)
    s = ("ok" if out else "auth_failed" if st & {401, 403} else "rate_limited" if 429 in st
         else "unreachable" if "exc" in st or any(isinstance(x, int) and x >= 500 for x in st) else "no_data")
    if S.get(name) != "ok": S[name] = s
    return out

def q(n, t="A"):
    try: return [str(x).strip('"').replace('" "', "") for x in RS.resolve(n, t)]
    except Exception: return []

# ---------------------------------------------------------------- helpers
def kind(t):
    try: ipaddress.ip_address(t); return "ip"
    except ValueError: pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", t): return "hash"
    if re.fullmatch(r"([a-z0-9-]+\.)+[a-z0-9-]{2,}", t, re.I) and not t.rsplit(".", 1)[-1].isdigit(): return "domain"
    return "username"

def pub(ip):
    try: return ipaddress.ip_address(ip).is_global
    except ValueError: return False

def host_ok(h):  # SSRF guard: only touch hosts whose every address is public
    ips = [h] if kind(h) == "ip" else q(h) + q(h, "AAAA")
    return bool(ips) and all(pub(i) for i in ips)

def _dt(s):
    try: return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception: return None

def ts(n):
    try: return dt.datetime.fromtimestamp(int(n), dt.timezone.utc).strftime("%Y-%m-%d")
    except Exception: return None

def lev(a, b):
    p = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        c = [i]
        for j, y in enumerate(b, 1): c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (x != y)))
        p = c
    return p[-1]

def ent(s):
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0

def sld(d):
    p = d.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"): return p[-3]
    return p[-2] if len(p) >= 2 else p[0]

def lookalike(d):
    lab, out, tbl = sld(d), [], str.maketrans("0135", "oles")
    N = lambda s: s.replace("rn", "m").replace("vv", "w").translate(tbl)
    if "xn--" in d: out.append("IDN/punycode label (possible homograph attack)")
    for b in BRANDS:
        if lab == b: continue
        dist = lev(lab, b)
        if N(lab) == N(b): out.append(f"homoglyph look-alike of '{b}'")
        elif (len(b) >= 6 and dist <= 1) or (len(b) >= 9 and dist <= 2): out.append(f"typosquat of '{b}' (edit distance {dist})")
    if len(lab) >= 12 and ent(lab) >= 3.6: out.append(f"high-entropy label '{lab}' (possible DGA)")
    if d.rsplit(".", 1)[-1] in RISKY_TLD: out.append(f"abuse-prone TLD .{d.rsplit('.', 1)[-1]}")
    return out

def safe_get(url, hops=5):  # manual redirects so every hop is re-checked against the SSRF guard
    hist = []
    for _ in range(hops):
        if not host_ok(urlparse(url).hostname or ""): return None, "", hist, url
        r = requests.get(url, headers=UA, timeout=7, allow_redirects=False, stream=True)
        if r.is_redirect and r.headers.get("Location"):
            hist.append(r.status_code); url = urljoin(url, r.headers["Location"]); r.close(); continue
        body = next(r.iter_content(30000), b"").decode("utf-8", "ignore")
        return r, body, hist, url
    return None, "", hist, url

# ---------------------------------------------------------------- passive / low-touch collectors
def rdap(d):
    j = G(f"https://rdap.org/domain/{d}", timeout=10) or {}
    if not j: return None
    ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    reg = "unknown"
    for e in j.get("entities", []):
        if "registrar" in e.get("roles", []):
            for v in e.get("vcardArray", [0, []])[1]:
                if v[0] == "fn": reg = v[3]
    c = _dt(ev.get("registration") or "")
    return {"registrar": reg, "created": ev.get("registration"), "expires": ev.get("expiration"), "age_days": (NOW() - c).days if c else None,
            "status": j.get("status", []), "dnssec_signed": (j.get("secureDNS") or {}).get("delegationSigned"), "source": "RDAP"}

def sub_probe(x):
    a, c = q(x), q(x, "CNAME")
    return a, (c[0].rstrip(".").lower() if c else None)

def subs(d):
    s = set()
    for c in G(f"https://crt.sh/?q=%25.{d}&output=json", timeout=25, tries=1) or []:
        s.update(n.strip().lower().lstrip("*.") for n in c.get("name_value", "").split("\n"))
    t = X("GET", f"https://api.hackertarget.com/hostsearch/?q={d}", fmt="text", timeout=10) or ""
    if not re.search(r"error|API count", t[:60], re.I): s.update(l.split(",")[0].lower() for l in t.splitlines())
    s = sorted(x for x in s if x.endswith("." + d) and re.fullmatch(r"[a-z0-9.-]+", x))
    wild = bool(q("zz" + "".join(random.choices(string.ascii_lowercase, k=10)) + "." + d))
    live, dang = {}, []
    if not wild:
        with TP(20) as e:
            for x, (ips, cn) in zip(s[:200], e.map(sub_probe, s[:200])):
                if ips: live[x] = ips
                elif cn and not q(cn):  # CNAME that leads nowhere -> candidate takeover
                    dang.append({"subdomain": x, "cname": cn, "provider": next((p for p in TAKE if p in cn), None)})
    return {"candidates": len(s), "wildcard_dns": wild, "live": live, "dangling_cnames": dang}

def mailsec(t):
    sel = ("default", "google", "selector1", "selector2", "k1", "s1", "s2", "mandrill", "mail", "dkim", "smtp")
    with TP(8) as e: dk = list(e.map(lambda s: (s, q(f"{s}._domainkey.{t}", "TXT")), sel))
    return {"dmarc": next((x for x in q("_dmarc." + t, "TXT") if x.startswith("v=DMARC1")), None),
            "mta_sts": next((x for x in q("_mta-sts." + t, "TXT") if x.startswith("v=STSv1")), None),
            "dkim_selectors": [s for s, v in dk if any("p=" in x for x in v)]}

def tls(d):
    if not host_ok(d): return {"valid": None, "error": "non-public host skipped"}
    try:
        with socket.create_connection((d, 443), timeout=5) as s, ssl.create_default_context().wrap_socket(s, server_hostname=d) as w:
            x, ver = w.getpeercert(), w.version()
        exp = dt.datetime.strptime(x["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        return {"valid": True, "issuer": dict(i[0] for i in x["issuer"]).get("organizationName"), "protocol": ver,
                "expires": exp.date().isoformat(), "days_left": (exp - NOW()).days, "san": [v for _, v in x.get("subjectAltName", [])][:15]}
    except ssl.SSLCertVerificationError as e: return {"valid": False, "error": e.verify_message}
    except Exception as e: return {"valid": None, "error": type(e).__name__}

def http(d):
    r = None
    for sch in ("https", "http"):
        try: r, body, hist, final = safe_get(f"{sch}://{d}")
        except Exception: continue
        if r is not None: break
    if r is None: return None
    t = re.search(r"<title[^>]*>(.*?)</title>", body[:20000], re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body[:20000], re.I)
    need = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]
    try: ck = r.raw.headers.getlist("Set-Cookie")
    except Exception: ck = []
    out = {"status": r.status_code, "final_url": final, "redirects": len(hist), "server": r.headers.get("Server"),
           "powered_by": r.headers.get("X-Powered-By"), "generator": gen and gen.group(1)[:60],
           "title": t and re.sub(r"\s+", " ", t.group(1)).strip()[:90], "missing_security_headers": [n for n in need if n not in r.headers],
           "weak_cookies": sum(1 for c in ck if "secure" not in c.lower() or "httponly" not in c.lower())}
    r.close(); return out

def dnsbl(ip):
    if ":" in ip: return []
    r, out = ".".join(reversed(ip.split("."))), []
    for z in BL:
        a = q(f"{r}.{z}")
        if a and not a[0].startswith("127.255.255."): out.append(z)  # 127.255.255.x = resolver blocked, not a listing
    return out

def revip(ip):
    t = X("GET", f"https://api.hackertarget.com/reverseiplookup/?q={ip}", fmt="text", timeout=10) or ""
    if re.search(r"error|API count|No DNS", t[:80], re.I): return []
    return [l.strip().lower() for l in t.splitlines()[:25] if re.fullmatch(r"[a-z0-9.-]+", l.strip().lower())]

def gravatar(e):
    h = hashlib.md5(e.encode()).hexdigest()
    try: r = requests.head(f"https://www.gravatar.com/avatar/{h}?d=404", headers=UA, timeout=6); _note(r.status_code)
    except requests.RequestException: _note("exc"); return None
    return {"profile": f"https://gravatar.com/{h}"} if r.status_code == 200 else None

# ---------------------------------------------------------------- keyed threat-intel sources
def VT(path, **params):
    k = os.getenv("VT_API_KEY")
    return k and X("GET", f"https://www.virustotal.com/api/v3/{path}", lim=VTL, headers={"x-apikey": k}, params=params or None)

def vt(kd, v):
    if kd == "url": v = base64.urlsafe_b64encode(v.encode()).decode().strip("=")
    a = ((VT(f"{EP[kd]}/{v}") or {}).get("data") or {}).get("attributes")
    if not a: return None
    ptc, res = a.get("popular_threat_classification") or {}, a.get("last_analysis_results") or {}
    o = {"stats": a.get("last_analysis_stats", {}), "reputation": a.get("reputation"), "votes": a.get("total_votes"),
         "name": a.get("meaningful_name"), "type": a.get("type_description"), "label": ptc.get("suggested_threat_label"),
         "threat_names": [x["value"] for x in ptc.get("popular_threat_name", [])[:5]],
         "threat_categories": [x["value"] for x in ptc.get("popular_threat_category", [])[:5]],
         "detections": [f"{e}: {r['result']}" for e, r in res.items() if r.get("category") == "malicious" and r.get("result")][:10],
         "tags": (a.get("tags") or [])[:12], "last_analysis": ts(a.get("last_analysis_date"))}
    if kd == "hash":
        sb = a.get("sandbox_verdicts") or {}
        o.update(names=(a.get("names") or [])[:6], size=a.get("size"), first_seen=ts(a.get("first_submission_date")), sha256=a.get("sha256"),
                 sha1=a.get("sha1"), md5=a.get("md5"), signed=(a.get("signature_info") or {}).get("verified"),
                 sandbox={n: x.get("category") for n, x in sb.items()})
    elif kd == "domain":
        o.update(registrar=a.get("registrar"), created=ts(a.get("creation_date")), popularity=a.get("popularity_ranks"),
                 vendor_categories=[c for c, _ in Counter((a.get("categories") or {}).values()).most_common(5)])
    elif kd == "ip": o.update(asn=a.get("asn"), as_owner=a.get("as_owner"), country=a.get("country"), network=a.get("network"))
    else: o.update(title=a.get("title"), final_url=a.get("last_final_url"), times_submitted=a.get("times_submitted"),
                   vendor_categories=[c for c, _ in Counter((a.get("categories") or {}).values()).most_common(5)])
    return o

def vt_pdns(kd, v):  # passive DNS: historical IPs of a domain / historical hostnames of an IP
    out = []
    for x in (VT(f"{EP[kd]}/{v}/resolutions", limit=15) or {}).get("data", []):
        a = x.get("attributes") or {}
        val = a.get("ip_address") or a.get("host_name")
        if val: out.append({"value": val, "date": ts(a.get("date"))})
    return out

def vt_rel(h, rel): return [x["id"] for x in (VT(f"files/{h}/{rel}", limit=10) or {}).get("data", []) if x.get("id")]

def abuse(ip):
    k = os.getenv("ABUSEIPDB_KEY")
    if not k: return None
    d = (X("GET", "https://api.abuseipdb.com/api/v2/check", headers={"Key": k, "Accept": "application/json"},
           params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}) or {}).get("data")
    if not d: return None
    cats = Counter(c for r in d.get("reports") or [] for c in r.get("categories", []))
    o = {x: y for x, y in d.items() if x != "reports"}  # drop raw reports (free-text comments from third parties)
    o["top_categories"] = [f"{ABCAT.get(c, c)} x{n}" for c, n in cats.most_common(5)]
    return o

def abusech(ep, **data):
    k = os.getenv("ABUSECH_KEY")
    if not k: return None
    r = X("POST", ep, headers={"Auth-Key": k}, data=data)
    return None if r is None else (r if r.get("query_status") == "ok" else {})

def uhost(h):
    r = abusech("https://urlhaus-api.abuse.ch/v1/host/", host=h)
    if not r: return r
    return {"url_count": r.get("url_count"), "first_seen": r.get("firstseen"), "blacklists": r.get("blacklists"),
            "urls": [{x: u.get(x) for x in ("url", "url_status", "threat", "date_added", "tags")} for u in (r.get("urls") or [])[:8]]}

def uurl(u):
    r = abusech("https://urlhaus-api.abuse.ch/v1/url/", url=u)
    if not r: return r
    return {"url_status": r.get("url_status"), "threat": r.get("threat"), "tags": r.get("tags"), "date_added": r.get("date_added"),
            "host": r.get("host"), "reference": r.get("urlhaus_reference"),
            "payloads": [{x: p.get(x) for x in ("filename", "file_type", "response_sha256", "signature")} for p in (r.get("payloads") or [])[:6]]}

def upay(h):
    r = abusech("https://urlhaus-api.abuse.ch/v1/payload/", **{("md5_hash" if len(h) == 32 else "sha256_hash"): h})
    if not r: return r
    return {"file_type": r.get("file_type"), "signature": r.get("signature"), "first_seen": r.get("firstseen"), "url_count": r.get("url_count"),
            "urls": [{x: u.get(x) for x in ("url", "url_status", "filename")} for u in (r.get("urls") or [])[:6]]}

def tfox(term):
    k = os.getenv("ABUSECH_KEY")
    if not k: return None
    r = X("POST", "https://threatfox-api.abuse.ch/api/v1/", headers={"Auth-Key": k}, json={"query": "search_ioc", "search_term": term, "exact_match": False})
    if r is None: return None
    d = r.get("data")
    if r.get("query_status") != "ok" or not isinstance(d, list): return {}
    return {"count": len(d), "iocs": [{f: x.get(f) for f in ("ioc", "ioc_type", "threat_type", "malware_printable", "confidence_level", "first_seen", "last_seen", "tags")} for x in d[:10]]}

def otx(kd, v):  # AlienVault OTX works anonymously (rate-limited)
    seg = {"ip": "IPv6" if ":" in v else "IPv4", "domain": "domain", "hash": "file"}[kd]
    j = G(f"https://otx.alienvault.com/api/v1/indicators/{seg}/{v}/general")
    if not j: return None
    pi = j.get("pulse_info") or {}; ps = pi.get("pulses") or []
    fam = {(m.get("display_name") if isinstance(m, dict) else m) for p in ps for m in p.get("malware_families", [])}
    return {"pulses": pi.get("count", 0), "names": [p.get("name") for p in ps[:5]], "adversaries": sorted({p["adversary"] for p in ps if p.get("adversary")})[:5],
            "families": sorted(x for x in fam if x)[:8], "tags": [t for t, _ in Counter(t for p in ps for t in p.get("tags", [])).most_common(8)],
            "validated_benign": bool(j.get("validation"))}

# ---------------------------------------------------------------- shared finding builders
def uh_find(F, who, uh):
    if not uh: return
    n = int(uh.get("url_count") or 0); on = sum(1 for u in uh.get("urls", []) if u.get("url_status") == "online")
    if n: F.append(("critical" if on else "high", f"{who} is tied to {n} URLhaus malware URL(s)" + (f", {on} online now" if on else "")))
    bl = {k: v for k, v in (uh.get("blacklists") or {}).items() if v and v != "not listed"}
    if bl: F.append(("high", f"{who} on URL blocklists: " + ", ".join(f"{k}={v}" for k, v in bl.items())))

def tf_find(F, who, tf):
    if tf and tf.get("count"):
        fam = sorted({i.get("malware_printable") for i in tf["iocs"] if i.get("malware_printable")})
        typ = sorted({i.get("threat_type") for i in tf["iocs"] if i.get("threat_type")})
        F.append(("critical", f"{who} is a ThreatFox IOC: {', '.join(fam) or 'unlabelled'} ({', '.join(typ) or 'n/a'})"))

def otx_find(F, who, o, lo=3):
    if not o or o.get("validated_benign") or (o.get("pulses") or 0) < lo: return
    n = o["pulses"]; fam = o.get("families") or []
    F.append(("high" if n >= 15 else "medium", f"{who} appears in {n} AlienVault OTX pulse(s)" + (f" ({', '.join(fam[:3])})" if fam else "")))

def vt_find(F, who, v, hi=5):
    if not v: return
    st = v.get("stats", {}); mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    if mal: F.append(("critical" if mal >= hi else "high", f"{who} flagged malicious by {mal} VirusTotal engines" + (f" ({v['label']})" if v.get("label") else "")))
    elif sus >= 3: F.append(("medium", f"{who} flagged suspicious by {sus} VirusTotal engines"))
    if any(re.search(r"phish|malware|malicious|botnet|command", c, re.I) for c in v.get("vendor_categories") or []):
        F.append(("high", f"{who} categorised as {', '.join(v['vendor_categories'][:2])} by security vendors"))

# ---------------------------------------------------------------- IP profiling
def ipintel(ip, F, log, link, S):
    if not pub(ip):
        F.append(("info", f"{ip} is a private/reserved address - external intelligence not applicable"))
        return dict(geo={}, ports=[], cves=[], tags=[], hostnames=[], cpes=[], greynoise=None, blacklists=[], abuseipdb=None, virustotal=None,
                    urlhaus=None, threatfox=None, otx=None, passive_dns=None, cohosted=[], note="non-public address")
    log(f"[*] profiling {ip}: geo/asn, internetdb, greynoise, dnsbl, abuseipdb, virustotal, abuse.ch, otx, pdns")
    with TP(12) as e:
        R = lambda n, fn, *a, key=None, **kw: e.submit(run, S, n, fn, *a, key=key, **kw)
        f = dict(geo=R("ip-api", G, f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,reverse,proxy,hosting,lat,lon"),
                 db=R("shodan_internetdb", G, f"https://internetdb.shodan.io/{ip}"), gn=R("greynoise", G, f"https://api.greynoise.io/v3/community/{ip}"),
                 bl=R("dnsbl", dnsbl, ip), ab=R("abuseipdb", abuse, ip, key="ABUSEIPDB_KEY"), vt=R("virustotal", vt, "ip", ip, key="VT_API_KEY"),
                 pd=R("vt_passive_dns", vt_pdns, "ip", ip, key="VT_API_KEY"), uh=R("urlhaus", uhost, ip, key="ABUSECH_KEY"),
                 tf=R("threatfox", tfox, ip, key="ABUSECH_KEY"), ox=R("otx", otx, "ip", ip), rv=R("reverse_ip", revip, ip))
        r = {k: v.result() for k, v in f.items()}
    g, db, gn, a = r["geo"] or {}, r["db"] or {}, r["gn"] or {}, r["ab"]
    if g.get("status") == "fail": g = {}
    tags, ports, cves = db.get("tags", []), db.get("ports", []), db.get("vulns", [])
    if g.get("as"): link(ip, g["as"].split()[0], "asn")
    for p in ports[:8]: link(ip, f"{ip}:{p}", "port")
    for c in cves[:6]: link(ip, c, "cve")
    for x in (r["pd"] or [])[:8]: link(ip, x["value"], "history")
    for h in (r["rv"] or [])[:10]: link(ip, h, "cohosted")
    if cves: F.append(("high", f"{ip}: {len(cves)} known CVE(s) exposed ({', '.join(cves[:4])})"))
    risky = [f"{p}/{RISKY[p]}" for p in ports if p in RISKY]
    if risky: F.append(("medium", f"{ip}: risky services exposed - {', '.join(risky)}"))
    if {"malware", "c2", "botnet"} & set(tags): F.append(("high", f"{ip}: tagged {', '.join(tags)} by Shodan InternetDB"))
    if "tor" in tags or (a or {}).get("isTor"): F.append(("medium", f"{ip} is a Tor node"))
    if g.get("proxy"): F.append(("medium", f"{ip} is a proxy/VPN endpoint"))
    if g.get("hosting"): F.append(("info", f"{ip} is in a hosting/datacenter range ({g.get('isp')})"))
    if gn.get("classification") == "malicious": F.append(("high", f"{ip}: GreyNoise classifies as malicious ({gn.get('name')})"))
    elif gn.get("riot"): F.append(("info", f"{ip} is a known benign service per GreyNoise RIOT ({gn.get('name')})"))
    if r["bl"]: F.append(("high", f"{ip} listed on {len(r['bl'])} DNSBL(s): {', '.join(r['bl'])}"))
    if a and a.get("abuseConfidenceScore", 0) >= 25:
        F.append(("critical" if a["abuseConfidenceScore"] >= 75 else "high",
                  f"{ip}: AbuseIPDB confidence {a['abuseConfidenceScore']}% ({a.get('totalReports')} reports; {', '.join(a['top_categories'][:3]) or 'no categories'})"))
    vt_find(F, ip, r["vt"]); uh_find(F, ip, r["uh"]); tf_find(F, ip, r["tf"]); otx_find(F, ip, r["ox"])
    return {"geo": g, "ports": ports, "cves": cves, "tags": tags, "hostnames": db.get("hostnames", []), "cpes": db.get("cpes", [])[:8],
            "greynoise": gn or None, "blacklists": r["bl"], "abuseipdb": a, "virustotal": r["vt"], "urlhaus": r["uh"], "threatfox": r["tf"],
            "otx": r["ox"], "passive_dns": r["pd"], "cohosted": r["rv"]}

def probe(name, url, u):
    def g(x):
        try: return requests.get(url.format(x), headers=UA, timeout=7).status_code
        except Exception: return None
    return name, url.format(u), g(u), g("".join(random.choices(string.ascii_lowercase, k=14)) + "x9")

# ---------------------------------------------------------------- orchestrator
def investigate(target, log=lambda m: None):
    raw = target.strip(); url = email = None
    F, D, nodes, edges, S = [], {}, {}, [], {}
    def link(a, b, g): nodes.setdefault(b, g); edges.append({"from": a, "to": b})
    if re.match(r"https?://", raw, re.I): url = raw; t = (urlparse(raw).hostname or "").lower().rstrip(".")
    elif re.fullmatch(r"[^@\s/]+@[^@\s/]+\.[^@\s/]{2,}", raw): email = raw.lower(); t = email.rsplit("@", 1)[1]
    else: t = raw.lower().split("/")[0].rstrip(".")
    if not t: raise ValueError("could not parse target")
    if not t.isascii():
        try: t = t.encode("idna").decode()
        except UnicodeError: pass
    base = kind(t); k = "url" if url else "email" if email else base
    root = url or email or t
    nodes[root] = k
    if root != t: link(root, t, base)
    log(f"[+] target locked: {root}  type={k}")

    def dom():
        log("[*] launching parallel collectors: dns, mail-auth, rdap, ct-logs, tls, http, threat feeds")
        with TP(14) as e:
            R = lambda n, fn, *a, key=None, **kw: e.submit(run, S, n, fn, *a, key=key, **kw)
            fs = dict(dns=R("dns", lambda: {r: q(t, r) for r in ("A", "AAAA", "MX", "NS", "TXT", "CAA")}), mail=R("mail_auth", mailsec, t),
                      whois=R("rdap", rdap, t), subs=R("subdomains", subs, t), tls=R("tls", tls, t), http=R("http", http, t),
                      vt=R("virustotal", vt, "domain", t, key="VT_API_KEY"), pd=R("vt_passive_dns", vt_pdns, "domain", t, key="VT_API_KEY"),
                      uh=R("urlhaus", uhost, t, key="ABUSECH_KEY"), tf=R("threatfox", tfox, t, key="ABUSECH_KEY"), ox=R("otx", otx, "domain", t))
            c = {n: f.result() for n, f in fs.items()}
        d = c["dns"] or {x: [] for x in ("A", "AAAA", "MX", "NS", "TXT", "CAA")}
        w, ms, tl, ht = c["whois"] or {}, c["mail"] or {}, c["tls"] or {}, c["http"]
        sb = c["subs"] or {"candidates": 0, "wildcard_dns": False, "live": {}, "dangling_cnames": []}
        spf = next((x for x in d["TXT"] if x.startswith("v=spf1")), None); dmarc = ms.get("dmarc")
        pol, pct = re.search(r"\bp=(\w+)", dmarc or ""), re.search(r"\bpct=(\d+)", dmarc or "")
        la = lookalike(t)
        D.update(dns=d, email_security={"spf": spf, "dmarc": dmarc, "dmarc_policy": pol and pol.group(1), "dmarc_pct": pct and int(pct.group(1)),
                                        "mta_sts": ms.get("mta_sts"), "dkim_selectors": ms.get("dkim_selectors", [])},
                 whois=w, subdomains=sb, tls=tl, http=ht, virustotal=c["vt"], passive_dns=c["pd"], urlhaus=c["uh"], threatfox=c["tf"],
                 otx=c["ox"], lookalike=la, ips={})
        log(f"[+] dns: {len(d['A'])} A / {len(d['MX'])} MX / {len(d['NS'])} NS | subdomains: {sb['candidates']} found, {len(sb['live'])} live")
        for ip in (d["A"][:3] + d["AAAA"][:1]): link(t, ip, "ip"); D["ips"][ip] = ipintel(ip, F, log, link, S)
        for n in d["NS"]: link(t, n.rstrip("."), "ns")
        for m in d["MX"]: link(t, m.split()[-1].rstrip("."), "mx")
        for s in list(sb["live"])[:12]: link(t, s, "subdomain")
        for x in (c["pd"] or [])[:8]: link(t, x["value"], "history")
        age = w.get("age_days")
        if age is not None and age < 30: F.append(("high", f"Newly registered domain ({age} days old)"))
        elif age is not None and age < 180: F.append(("medium", f"Young domain ({age} days old)"))
        if not d["A"] and not d["AAAA"]: F.append(("low", "Domain does not resolve"))
        if not spf: F.append(("medium", "No SPF record - email spoofing possible"))
        elif "+all" in spf: F.append(("high", "SPF allows any sender (+all)"))
        elif "-all" not in spf: F.append(("low", "SPF is not strictly enforced"))
        if not dmarc: F.append(("medium", "No DMARC record"))
        elif pol and pol.group(1) == "none": F.append(("low", "DMARC is monitor-only (p=none)"))
        if pct and int(pct.group(1)) < 100 and pol and pol.group(1) != "none": F.append(("low", f"DMARC applies to only {pct.group(1)}% of mail"))
        if w.get("dnssec_signed") is False: F.append(("info", "DNSSEC is not enabled"))
        if tl.get("valid") is False: F.append(("high", f"TLS certificate invalid: {tl.get('error')}"))
        elif tl.get("days_left") is not None and tl["days_left"] < 14: F.append(("high" if tl["days_left"] < 0 else "medium", f"TLS certificate expires in {tl['days_left']} days"))
        if tl.get("protocol") in ("TLSv1", "TLSv1.1"): F.append(("medium", f"Legacy TLS protocol negotiated ({tl['protocol']})"))
        if ht and len(ht["missing_security_headers"]) >= 4: F.append(("low", f"Missing security headers: {', '.join(ht['missing_security_headers'])}"))
        if ht and ht.get("weak_cookies"): F.append(("low", f"{ht['weak_cookies']} cookie(s) set without Secure/HttpOnly"))
        if ht and ht.get("server") and re.search(r"\d+\.\d+", ht["server"]): F.append(("low", f"Server version disclosed: {ht['server']}"))
        if len(sb["live"]) > 40: F.append(("low", f"Large attack surface: {len(sb['live'])} live subdomains"))
        for dg in sb["dangling_cnames"][:6]:
            F.append(("high" if dg["provider"] else "medium", f"Dangling CNAME {dg['subdomain']} -> {dg['cname']}" + (f" ({dg['provider']}: possible subdomain takeover)" if dg["provider"] else "")))
        if re.search(r"(login|secure|verify|account|update).*(paypal|bank|apple|microsoft|google|amazon)|(paypal|bank|apple|microsoft|google|amazon).*(login|secure|verify|account)", " ".join([t] + list(sb["live"]))):
            F.append(("high", "Brand-impersonation keywords in domain/subdomain names"))
        for x in la: F.append(("high" if re.match(r"typosquat|homoglyph", x) else "low" if x.startswith(("high-entropy", "abuse-prone")) else "medium", f"Look-alike signal: {x}"))
        vt_find(F, "Domain", c["vt"]); uh_find(F, "Domain", c["uh"]); tf_find(F, "Domain", c["tf"]); otx_find(F, "Domain", c["ox"])

    def ipb():
        D["ips"] = {t: ipintel(t, F, log, link, S)}
        try: ptr = str(RS.resolve(dns.reversename.from_address(t), "PTR")[0]); D["ptr"] = ptr; link(t, ptr, "ptr")
        except Exception: D["ptr"] = None

    def hsh():
        al = {32: "md5", 40: "sha1", 64: "sha256"}[len(t)]
        log(f"[*] hash type {al}: VirusTotal, MalwareBazaar, ThreatFox, URLhaus, OTX, CIRCL hashlookup")
        with TP(8) as e:
            R = lambda n, fn, *a, key=None, **kw: e.submit(run, S, n, fn, *a, key=key, **kw)
            fs = dict(v=R("virustotal", vt, "hash", t, key="VT_API_KEY"), mb=R("malwarebazaar", abusech, "https://mb-api.abuse.ch/api/v1/", query="get_info", hash=t, key="ABUSECH_KEY"),
                      ci=R("circl_hashlookup", G, f"https://hashlookup.circl.lu/lookup/{al}/{t}"), tf=R("threatfox", tfox, t, key="ABUSECH_KEY"),
                      ox=R("otx", otx, "hash", t))
            if len(t) in (32, 64): fs["up"] = R("urlhaus", upay, t, key="ABUSECH_KEY")
            c = {n: f.result() for n, f in fs.items()}
        v, mb, ci, tf, up, ox = c["v"], c["mb"], c["ci"], c["tf"], c.get("up"), c["ox"]
        if mb: mb = {x: (mb.get("data") or [{}])[0].get(x) for x in ("sha256_hash", "file_name", "file_size", "file_type", "signature", "first_seen", "delivery_method", "tags", "reporter")}
        if mb and not mb.get("sha256_hash") and not mb.get("signature"): mb = {}
        D.update(virustotal=v, malwarebazaar=mb, threatfox=tf, urlhaus_payload=up, otx=ox, circl_hashlookup=ci)
        vt_find(F, "File", v, hi=10)
        smal = [n for n, sv in ((v or {}).get("sandbox") or {}).items() if sv == "malicious"]
        if smal: F.append(("high", f"{len(smal)} VirusTotal sandbox(es) returned a malicious verdict ({', '.join(smal[:3])})"))
        if mb: F.append(("critical", f"Known malware in MalwareBazaar: {mb.get('signature') or 'unlabelled'} ({mb.get('file_type')})")); link(t, mb.get("signature") or "family", "family")
        tf_find(F, "File hash", tf); otx_find(F, "File hash", ox, lo=1)
        if up:
            F.append(("critical", f"File is distributed from {up.get('url_count')} URLhaus URL(s) ({up.get('signature') or up.get('file_type')})"))
            for u in up.get("urls", [])[:5]:
                if u.get("url"): link(t, u["url"], "url")
        if ci: F.append(("info", f"Known-file entry in CIRCL hashlookup: {ci.get('FileName') or ci.get('source') or 'trusted source'}"))
        if v:
            for h2 in (v.get("sha256"), v.get("sha1"), v.get("md5")):
                if h2 and h2 != t: link(t, h2, "hash")
            if v.get("stats", {}).get("malicious", 0):
                with TP(2) as e:
                    fd = e.submit(run, S, "vt_contacted_domains", vt_rel, t, "contacted_domains", key="VT_API_KEY")
                    fi = e.submit(run, S, "vt_contacted_ips", vt_rel, t, "contacted_ips", key="VT_API_KEY")
                    cd, cip = fd.result() or [], fi.result() or []
                D["network_iocs"] = {"contacted_domains": cd, "contacted_ips": cip}
                for x in cd[:8] + cip[:8]: link(t, x, "contacted")
                if cd or cip: F.append(("medium", f"Sample contacts {len(cd)} domain(s) and {len(cip)} IP(s) at runtime (see IOC graph)"))
        if not (v or mb or ci or tf or up): F.append(("info", "No hash intelligence returned - the hash may simply be unknown"))

    def usr():
        log(f"[*] probing {len(SITES)} platforms with false-positive control")
        with TP(12) as e: rs = list(e.map(lambda s: probe(s[0], s[1], t), SITES.items()))
        found = [{"site": n, "url": u} for n, u, a, b in rs if a == 200 and b == 404]
        D["profiles"] = {"found": found, "unverifiable": [n for n, u, a, b in rs if a == 200 and b != 404], "checked": len(rs)}
        for p in found: link(t, p["site"], "profile")
        F.append(("info", f"{len(found)} verified profile(s) of {len(rs)} checked. A match is not proof of identity"))

    {"domain": dom, "ip": ipb, "hash": hsh}.get(base, usr)()

    if url:  # URL-specific feeds on top of host analysis
        log("[*] URL feeds: URLhaus, VirusTotal")
        with TP(2) as e:
            fu = e.submit(run, S, "urlhaus_url", uurl, url, key="ABUSECH_KEY"); fv = e.submit(run, S, "virustotal_url", vt, "url", url, key="VT_API_KEY")
            uu, vu = fu.result(), fv.result()
        D["url_intel"] = {"urlhaus": uu, "virustotal": vu}
        if uu:
            F.append(("critical" if uu.get("url_status") == "online" else "high", f"URLhaus lists this URL as {uu.get('threat') or 'malicious'} ({uu.get('url_status')})"))
            for p in uu.get("payloads", []):
                if p.get("response_sha256"): link(root, p["response_sha256"], "hash")
        vt_find(F, "URL", vu)
        if re.search(r"@|//[^/]*(\d{1,3}\.){3}\d{1,3}", url[:200]) or "xn--" in url: F.append(("medium", "URL uses obfuscation patterns (userinfo '@', raw IP host or punycode)"))
    if email:
        with TP(1) as e: gr = e.submit(run, S, "gravatar", gravatar, email).result()
        dsp, mx = t in DISPOSABLE, bool((D.get("dns") or {}).get("MX"))
        D["email"] = {"address": email, "disposable_domain": dsp, "domain_has_mx": mx, "gravatar": gr}
        if dsp: F.append(("medium", f"{t} is a disposable e-mail provider"))
        if D.get("dns") and not mx: F.append(("medium", f"{t} has no MX record - mailbox cannot receive mail"))
        if gr: F.append(("info", "Gravatar profile exists for this address")); link(root, gr["profile"], "profile")

    for n, s in S.items():
        if s == "auth_failed" and n in KEYED: F.append(("info", f"Source '{n}' rejected the API key - verify it"))
    if not [x for x in F if x[0] != "info"]: F.append(("info", "No adverse indicators from the enabled sources"))
    p = 1.0
    for s, _ in F: p *= 1 - SEV[s] / 100
    score = round(100 * (1 - p))
    level = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"
    ips = D.get("ips", {})
    healthy = sum(1 for s in S.values() if s in ("ok", "no_data")); live = sum(1 for s in S.values() if s != "no_key")
    stats = {"ips": len(ips), "live_subdomains": len(D.get("subdomains", {}).get("live", {})), "open_ports": sum(len(i["ports"]) for i in ips.values()),
             "cves": sum(len(i["cves"]) for i in ips.values()), "blacklists": sum(len(i["blacklists"]) for i in ips.values()),
             "adverse_findings": sum(1 for x in F if x[0] != "info"), "coverage": f"{round(100 * healthy / live)}%" if live else "n/a"}
    fl = [{"sev": s, "text": x} for s, x in sorted(F, key=lambda z: -SEV[z[0]])]
    log(f"[+] correlation complete: {len(edges)} relationships, risk score {score} ({level})")
    return {"target": root, "type": k, "data": D, "findings": fl, "alerts": [x for x in fl if x["sev"] in ("high", "critical")], "score": score, "level": level,
            "stats": stats, "sources": S, "summary": f"{k.upper()} {root}: {level.upper()} ({score}/100). {fl[0]['text']}",
            "graph": {"nodes": [{"id": n, "group": g} for n, g in nodes.items()], "edges": edges},
            "skipped": [x for x in KEYS if not os.getenv(x)], "time": NOW().strftime("%Y-%m-%d %H:%M UTC")}

# ---------------------------------------------------------------- exports
IOC_GROUPS = {"ip", "domain", "subdomain", "hash", "url", "cve", "ptr", "history", "cohosted", "contacted", "ns", "mx"}

def iocs_csv(r):
    parent = {e["to"]: e["from"] for e in r["graph"]["edges"]}
    o = io.StringIO(); w = csv.writer(o); w.writerow(["indicator", "type", "relationship", "linked_from", "investigation_root", "risk_score"])
    for n in r["graph"]["nodes"]:
        if n["group"] in IOC_GROUPS or n["id"] == r["target"]:
            v = n["id"]; typ = "cve" if n["group"] == "cve" else "url" if v.startswith("http") else kind(v)
            w.writerow([v, typ, n["group"], parent.get(v, ""), r["target"], r["score"]])
    return o.getvalue()

def stix(r):
    n = NOW().strftime("%Y-%m-%dT%H:%M:%S.000Z"); objs = []
    def ind(v):
        kd = kind(v)
        if v.startswith("http"): pat = "[url:value = '%s']" % v.replace("'", "%27")
        elif kd == "ip": pat = f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']"
        elif kd == "hash": alg = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(v)]; pat = f"[file:hashes.'{alg}' = '{v}']"
        elif kd == "domain": pat = f"[domain-name:value = '{v}']"
        else: return
        o = {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}", "created": n, "modified": n, "name": v, "pattern": pat,
             "pattern_type": "stix", "valid_from": n, "indicator_types": ["malicious-activity"], "confidence": r["score"]}
        if r["alerts"]: o["description"] = "; ".join(x["text"] for x in r["alerts"][:3])[:500]
        objs.append(o)
    if r["level"] in ("high", "critical"):  # only publish indicators we actually consider adverse
        ind(r["target"])
        for e in r["graph"]["edges"]:
            if e["from"] == r["target"] and r["type"] in ("url", "email"): ind(e["to"])
        for nd in r["graph"]["nodes"]:
            if nd["group"] == "contacted": ind(nd["id"])
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}

def report_md(r):
    L = [f"# Investigation Report: {r['target']}", f"*{r['time']} | type: {r['type']} | ThreatLens {VER}*", "",
         f"## Verdict\nRisk score **{r['score']}/100** ({r['level'].upper()}) | source coverage {r['stats']['coverage']}", "", f"> {r['summary']}", "", "## Findings"]
    L += [f"- **{f['sev'].upper()}** - {f['text']}" for f in r["findings"]]
    L += ["", "## Source status", "| source | status |", "|---|---|"] + [f"| {n} | {s} |" for n, s in sorted(r["sources"].items())]
    L += ["", "## IOC relationships"] + [f"- {e['from']} -> {e['to']}" for e in r["graph"]["edges"]]
    L += ["", "## Raw intelligence", "```json", json.dumps(r["data"], indent=1, default=str), "```"]
    return "\n".join(L)
