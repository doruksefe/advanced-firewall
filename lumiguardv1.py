"""
╔══════════════════════════════════════════════════════════════════╗
║          LUMİ GUARD VERSION 1.0                     ║
║  IPv6 · Fail2ban · Port Scan · DDoS · Log Rotation · Kalıcı DB  ║
╚══════════════════════════════════════════════════════════════════╝

Gereksinimler:
    pip install flask fail2ban-client   # fail2ban ayrıca kurulu olmalı
    sudo apt install fail2ban ufw -y

Çalıştırma:
    sudo python3 lumiguardv1.py
"""

import re, os, time, subprocess, json, urllib.request, sqlite3, secrets, logging, ipaddress
import logging.handlers
from collections import defaultdict
from threading import Thread, Timer, Lock
from flask import Flask, render_template_string, jsonify, request, Response
from functools import wraps
from datetime import datetime

# ══════════════════════════════════════════════════════════════════
# 1. KONFİGÜRASYON
# ══════════════════════════════════════════════════════════════════

# Log dosyası (SSH brute-force tespiti için)
if os.path.exists("/var/log/auth.log"):
    LOG_FILE = "/var/log/auth.log"
else:
    LOG_FILE = "/var/log/syslog"

# Kural eşikleri
FAILED_LIMIT      = 5       # Bu kadar başarısız denemeden sonra ban
BAN_TIME          = 3600    # Ban süresi (saniye) — 1 saat
PORTSCAN_LIMIT    = 15      # 60 saniyede bu kadar farklı porta istek → ban
PORTSCAN_WINDOW   = 60      # Port scan tespit penceresi (saniye)
DDOS_PKT_LIMIT    = 200     # 10 saniyede bu kadar istek → DDoS şüphesi
DDOS_WINDOW       = 10      # DDoS tespit penceresi (saniye)

# Güvenilir IP'ler (asla banlanmaz)
TRUSTED_IPS = ["127.0.0.1", "::1", "192.168.1.1"]

# Panel erişimi
PANEL_USER = "admin"
PANEL_PASS = "Lumi7#Qx123-4!"
LOGIN_ATTEMPT_LIMIT   = 5
LOGIN_LOCKOUT_SECONDS = 300   # 5 dakika

# İzin verilen panel ağları — boş = herkese açık
# Örnek: ["192.168.", "10.0."]
ALLOWED_PANEL_NETWORKS = []

# Fail2ban jail ismi (SSH için)
FAIL2BAN_SSH_JAIL = "sshd"

# Log rotation — dosyalar bu dizine yazılır
LOG_DIR      = "/var/log/siber_kalkan"
LOG_MAX_MB   = 10     # Tek dosya max boyutu
LOG_BACKUP   = 5      # Kaç eski log dosyası tutulsun

# ══════════════════════════════════════════════════════════════════
# 2. LOG ROTATION SİSTEMİ
# ══════════════════════════════════════════════════════════════════

os.makedirs(LOG_DIR, exist_ok=True)

_rot_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIR, "siber_kalkan.log"),
    maxBytes=LOG_MAX_MB * 1024 * 1024,
    backupCount=LOG_BACKUP,
    encoding="utf-8"
)
_rot_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logger = logging.getLogger("SiberKalkan")
logger.setLevel(logging.INFO)
logger.addHandler(_rot_handler)
logger.addHandler(logging.StreamHandler())   # Terminale de yaz

# ══════════════════════════════════════════════════════════════════
# 3. IP YARDIMCILARI — IPv4 + IPv6
# ══════════════════════════════════════════════════════════════════

def is_valid_ip(ip: str) -> bool:
    """IPv4 ve IPv6 adreslerini doğrular."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def normalize_ip(ip: str) -> str:
    """IPv6 adresini normalize eder (::1 → 0:0:0:0:0:0:0:1 gibi karışıklıkları önler)."""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip()

def is_ipv6(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip.strip()), ipaddress.IPv6Address)
    except ValueError:
        return False

# ══════════════════════════════════════════════════════════════════
# 4. VERİTABANI — KALICI İSTATİSTİK
# ══════════════════════════════════════════════════════════════════

DB_PATH = "siber_kalkan.db"
db_lock = Lock()

def init_db():
    with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS bans (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT    NOT NULL,
                    ip        TEXT    NOT NULL,
                    loc       TEXT,
                    reason    TEXT DEFAULT 'SSH Brute-Force',
                    ip_ver    TEXT DEFAULT 'IPv4'
                );

                CREATE TABLE IF NOT EXISTS daily_stats (
                    date      TEXT PRIMARY KEY,
                    total     INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS hourly_stats (
                    date      TEXT NOT NULL,
                    hour      INTEGER NOT NULL,
                    count     INTEGER DEFAULT 0,
                    PRIMARY KEY (date, hour)
                );
            """)
    logger.info("Veritabanı başlatıldı.")

init_db()

def db_record_ban(ip: str, loc: str, reason: str):
    """Ban kaydını veritabanına yazar ve istatistikleri günceller."""
    now       = datetime.now()
    ts        = now.strftime("%Y-%m-%d %H:%M:%S")
    today     = now.strftime("%Y-%m-%d")
    hour      = now.hour
    ip_ver    = "IPv6" if is_ipv6(ip) else "IPv4"

    with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO bans (timestamp, ip, loc, reason, ip_ver) VALUES (?,?,?,?,?)",
                (ts, ip, loc, reason, ip_ver)
            )
            conn.execute(
                "INSERT INTO daily_stats (date, total) VALUES (?,1) "
                "ON CONFLICT(date) DO UPDATE SET total = total + 1",
                (today,)
            )
            conn.execute(
                "INSERT INTO hourly_stats (date, hour, count) VALUES (?,?,1) "
                "ON CONFLICT(date, hour) DO UPDATE SET count = count + 1",
                (today, hour)
            )

def db_get_today_total() -> int:
    today = datetime.now().strftime("%Y-%m-%d")
    with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT total FROM daily_stats WHERE date=?", (today,)
            ).fetchone()
    return row[0] if row else 0

def db_get_hourly_today() -> list:
    today = datetime.now().strftime("%Y-%m-%d")
    with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT hour, count FROM hourly_stats WHERE date=?", (today,)
            ).fetchall()
    data = [0] * 24
    for hour, count in rows:
        data[hour] = count
    return data

def db_get_recent_bans(limit=20) -> list:
    with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT timestamp, ip, loc, reason, ip_ver FROM bans "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [
        {"time": r[0], "ip": r[1], "loc": r[2], "reason": r[3], "ip_ver": r[4]}
        for r in rows
    ]

# ══════════════════════════════════════════════════════════════════
# 5. KONUM SERVİSİ
# ══════════════════════════════════════════════════════════════════

location_cache = {}

def get_location(ip: str) -> str:
    norm = normalize_ip(ip)
    if norm in location_cache:
        return location_cache[norm]
    # Loopback / private adresler için API'ye gitme
    try:
        obj = ipaddress.ip_address(norm)
        if obj.is_loopback or obj.is_private:
            location_cache[norm] = "Yerel Ağ"
            return "Yerel Ağ"
    except ValueError:
        pass
    try:
        url = f"http://ip-api.com/json/{norm}?fields=city,country,status"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            loc = f"{data.get('city','?')}, {data.get('country','?')}"
        else:
            loc = "Bilinmiyor"
    except Exception:
        loc = "Lokasyon Alınamadı"
    location_cache[norm] = loc
    return loc

# ══════════════════════════════════════════════════════════════════
# 6. FAIL2BAN ENTEGRASYONU
# ══════════════════════════════════════════════════════════════════

def fail2ban_ban(ip: str, jail: str = FAIL2BAN_SSH_JAIL):
    """Fail2ban üzerinden IP'yi yasaklar."""
    try:
        subprocess.Popen(
            ["sudo", "fail2ban-client", "set", jail, "banip", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info(f"[FAIL2BAN] {ip} → {jail} jail'ine eklendi.")
    except Exception as e:
        logger.warning(f"[FAIL2BAN] Hata: {e}")

def fail2ban_unban(ip: str, jail: str = FAIL2BAN_SSH_JAIL):
    """Fail2ban üzerinden IP yasağını kaldırır."""
    try:
        subprocess.Popen(
            ["sudo", "fail2ban-client", "set", jail, "unbanip", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info(f"[FAIL2BAN] {ip} → {jail} jail'inden çıkarıldı.")
    except Exception as e:
        logger.warning(f"[FAIL2BAN] Unban hatası: {e}")

def fail2ban_status(jail: str = FAIL2BAN_SSH_JAIL) -> dict:
    """
    Fail2ban jail durumunu döndürür.
    fail2ban kurulu değilse veya sudo izni yoksa güvenli şekilde hata döner,
    asla exception fırlatmaz (Internal Server Error'u önler).
    """
    # fail2ban-client binary var mı kontrol et
    try:
        which = subprocess.run(
            ["which", "fail2ban-client"],
            capture_output=True, text=True, timeout=2
        )
        if which.returncode != 0:
            return {"output": "⚠️  fail2ban kurulu değil veya PATH'te bulunamadı.\n"
                              "Kurmak için: sudo apt install fail2ban -y", "ok": False}
    except Exception:
        return {"output": "⚠️  fail2ban-client bulunamadı.", "ok": False}

    # Durum sorgula
    try:
        result = subprocess.run(
            ["sudo", "fail2ban-client", "status", jail],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            output = f"Çıktı alınamadı (return code: {result.returncode})"
        return {"output": output, "ok": result.returncode == 0}
    except subprocess.TimeoutExpired:
        return {"output": "⚠️  fail2ban-client zaman aşımına uğradı (5s). "
                          "Servis çalışıyor mu? → sudo systemctl status fail2ban", "ok": False}
    except PermissionError:
        return {"output": "⚠️  sudo izni yok. Sudoers dosyasını kontrol edin.", "ok": False}
    except FileNotFoundError:
        return {"output": "⚠️  fail2ban-client bulunamadı.", "ok": False}
    except Exception as e:
        return {"output": f"⚠️  Beklenmedik hata: {e}", "ok": False}

# ══════════════════════════════════════════════════════════════════
# 7. UFW (IPv4 + IPv6) BAN / UNBAN
# ══════════════════════════════════════════════════════════════════

def ufw_ban(ip: str):
    norm = normalize_ip(ip)
    if not is_valid_ip(norm):
        logger.warning(f"[UFW] Geçersiz IP ban denemesi: {norm!r}")
        return
    subprocess.Popen(
        ["sudo", "ufw", "deny", "from", norm],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    logger.info(f"[UFW] {norm} engellendi.")

def ufw_unban(ip: str):
    norm = normalize_ip(ip)
    if not is_valid_ip(norm):
        logger.warning(f"[UFW] Geçersiz IP unban denemesi: {norm!r}")
        return
    subprocess.Popen(
        ["sudo", "ufw", "delete", "deny", "from", norm],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    logger.info(f"[UFW] {norm} engeli kaldırıldı.")

# ══════════════════════════════════════════════════════════════════
# 8. DDOS TESPİT MOTORU
#    Her IP için son N saniyedeki istek sayısını takip eder.
# ══════════════════════════════════════════════════════════════════

ddos_tracker: dict[str, list] = defaultdict(list)   # ip -> [timestamp, ...]
ddos_lock = Lock()

def ddos_check(ip: str) -> bool:
    """True dönerse bu IP DDoS şüphelisi sayılır ve banlanır."""
    now = time.time()
    with ddos_lock:
        ddos_tracker[ip] = [t for t in ddos_tracker[ip] if now - t < DDOS_WINDOW]
        ddos_tracker[ip].append(now)
        return len(ddos_tracker[ip]) >= DDOS_PKT_LIMIT

# ══════════════════════════════════════════════════════════════════
# 9. PORT SCAN TESPİT MOTORU
#    Kısa sürede çok sayıda farklı porta istek → port scan
# ══════════════════════════════════════════════════════════════════

portscan_tracker: dict[str, dict] = defaultdict(lambda: {"ports": set(), "first": 0.0})
portscan_lock = Lock()

def portscan_check(ip: str, port: int) -> bool:
    """True dönerse bu IP port taraması yapıyor sayılır."""
    now = time.time()
    with portscan_lock:
        entry = portscan_tracker[ip]
        if now - entry["first"] > PORTSCAN_WINDOW:
            entry["ports"] = set()
            entry["first"] = now
        entry["ports"].add(port)
        return len(entry["ports"]) >= PORTSCAN_LIMIT

# ══════════════════════════════════════════════════════════════════
# 10. MERKEZ BAN FONKSİYONU
# ══════════════════════════════════════════════════════════════════

def execute_ban(ip: str, reason: str = "SSH Brute-Force"):
    norm = normalize_ip(ip)
    if not is_valid_ip(norm):
        logger.warning(f"Geçersiz IP ban denemesi engellendi: {norm!r}")
        return
    if norm in [normalize_ip(t) for t in TRUSTED_IPS]:
        logger.info(f"[GÜVENLİ] {norm} beyaz listede. Müdahale edilmedi.")
        return

    konum = get_location(norm)

    # Veritabanına kaydet
    db_record_ban(norm, konum, reason)

    # UFW ile engelle (IPv4 ve IPv6 destekler)
    ufw_ban(norm)

    # Fail2ban ile de yasakla (SSH banlama için)
    if "SSH" in reason:
        fail2ban_ban(norm)

    logger.warning(f"🚨 [BAN] {norm} engellendi | Sebep: {reason} | Konum: {konum}")

    # BAN_TIME sonra otomatik unban
    Timer(BAN_TIME, execute_unban, [norm]).start()

def execute_unban(ip: str):
    norm = normalize_ip(ip)
    if not is_valid_ip(norm):
        return
    ufw_unban(norm)
    fail2ban_unban(norm)
    logger.info(f"🔓 [UNBAN] {norm} engeli kaldırıldı.")

# ══════════════════════════════════════════════════════════════════
# 11. SSH LOG MONİTÖRÜ (IPv4 + IPv6)
# ══════════════════════════════════════════════════════════════════

# IPv4 ve IPv6 adresleri eşleyen regex
IP_REGEX = re.compile(
    r"from\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})"
)

def monitor_logs():
    failed_attempts: dict[str, int] = defaultdict(int)
    logger.info(f"🚀 SSH MONITOR AKTİF: {LOG_FILE}")

    while True:
        try:
            with open(LOG_FILE, "r", errors="ignore") as log:
                log.seek(0, os.SEEK_END)
                while True:
                    line = log.readline()
                    if not line:
                        time.sleep(0.05)
                        continue

                    low = line.lower()
                    # SSH başarısız giriş
                    if "failed password" in low and "sshd[" in low:
                        m = IP_REGEX.search(line)
                        if m:
                            raw_ip = m.group(1)
                            if not is_valid_ip(raw_ip):
                                continue
                            ip = normalize_ip(raw_ip)
                            failed_attempts[ip] += 1
                            logger.info(f"🚩 SSH Tehdit: {ip} (Deneme #{failed_attempts[ip]})")
                            if failed_attempts[ip] >= FAILED_LIMIT:
                                Thread(
                                    target=execute_ban,
                                    args=(ip, "SSH Brute-Force"),
                                    daemon=True
                                ).start()
                                failed_attempts[ip] = -9999

        except Exception as e:
            logger.error(f"SSH monitor hatası: {e}. 5 sn sonra yeniden başlıyor...")
            time.sleep(5)

# ══════════════════════════════════════════════════════════════════
# 12. PORT SCAN + DDoS MONİTÖRÜ
#     UFW/syslog'dan bağlantı redlerini izler.
# ══════════════════════════════════════════════════════════════════

KERNEL_LOG = "/var/log/kern.log"

# UFW BLOCK logları birden fazla yerde olabilir; öncelik sırasıyla dene
UFW_LOG_CANDIDATES = [
    "/var/log/ufw.log",       # UFW'nin kendi log dosyası (en güvenilir)
    "/var/log/kern.log",      # Kernel log (Debian/Ubuntu)
    "/var/log/syslog",        # Genel fallback
    "/var/log/messages",      # RHEL/CentOS fallback
]

UFW_BLOCK_RE = re.compile(
    r"\[UFW BLOCK\].*?SRC=((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39}).*?DPT=(\d+)"
)

def _find_ufw_log() -> str | None:
    """Okunabilir UFW log dosyasını bulur. Bulamazsa None döner."""
    for path in UFW_LOG_CANDIDATES:
        if os.path.exists(path) and os.access(path, os.R_OK):
            return path
    return None

def monitor_ufw_blocks():
    """
    UFW'nin engellediği paketleri izleyerek port scan ve DDoS tespiti yapar.
    Log dosyası bulunamazsa veya erişilemezse uyarı verir ve pasif bekler
    — asla çökme döngüsüne girmez.
    """
    log_path = _find_ufw_log()

    if not log_path:
        logger.warning(
            "⚠️  UFW BLOCK log dosyası bulunamadı. "
            "UFW logging'i etkinleştirmek için:\n"
            "    sudo ufw logging on\n"
            "    sudo ufw reload\n"
            "Port scan ve DDoS tespiti bu oturum için devre dışı."
        )
        # Dosya oluşana kadar 60 saniyede bir kontrol et, sistemi meşgul etme
        while True:
            time.sleep(60)
            log_path = _find_ufw_log()
            if log_path:
                logger.info(f"✅ UFW log dosyası bulundu: {log_path}. Monitor başlatılıyor.")
                break

    logger.info(f"🔍 UFW BLOCK MONITOR AKTİF: {log_path}")

    while True:
        try:
            with open(log_path, "r", errors="ignore") as log:
                log.seek(0, os.SEEK_END)
                while True:
                    line = log.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    m = UFW_BLOCK_RE.search(line)
                    if not m:
                        continue

                    raw_ip   = m.group(1)
                    raw_port = m.group(2)

                    # Port sayısallaştırma güvenli
                    try:
                        port = int(raw_port)
                    except ValueError:
                        continue

                    if not is_valid_ip(raw_ip):
                        continue
                    ip = normalize_ip(raw_ip)

                    # DDoS kontrolü
                    if ddos_check(ip):
                        logger.warning(f"⚡ [DDoS] {ip} → {DDOS_PKT_LIMIT} istek/{DDOS_WINDOW}sn")
                        Thread(
                            target=execute_ban,
                            args=(ip, f"DDoS ({DDOS_PKT_LIMIT} req/{DDOS_WINDOW}s)"),
                            daemon=True
                        ).start()

                    # Port scan kontrolü
                    if portscan_check(ip, port):
                        logger.warning(f"🔭 [PORTSCAN] {ip} → {PORTSCAN_LIMIT}+ port/{PORTSCAN_WINDOW}sn")
                        Thread(
                            target=execute_ban,
                            args=(ip, f"Port Scan ({PORTSCAN_LIMIT} port/{PORTSCAN_WINDOW}s)"),
                            daemon=True
                        ).start()

        except PermissionError:
            logger.error(
                f"⛔ UFW log okuma izni yok: {log_path}\n"
                "Çözüm: sudo chmod o+r {log_path}  veya scripti sudo ile çalıştırın."
            )
            time.sleep(30)   # Sık hata basmadan bekle

        except FileNotFoundError:
            logger.warning(f"UFW log dosyası silindi veya taşındı: {log_path}. Yeniden arıyorum...")
            time.sleep(10)
            new_path = _find_ufw_log()
            if new_path:
                log_path = new_path
                logger.info(f"Yeni UFW log: {log_path}")

        except Exception as e:
            logger.error(f"UFW monitor beklenmedik hata: {e}. 10 sn sonra devam ediliyor.")
            time.sleep(10)   # Kısa bekleme, ama 5sn'de sonsuz döngüden daha iyi

# ══════════════════════════════════════════════════════════════════
# 13. PANEL AUTH + RATE LIMIT
# ══════════════════════════════════════════════════════════════════

login_attempts: dict[str, list] = defaultdict(list)

def is_login_locked(ip: str) -> bool:
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOGIN_LOCKOUT_SECONDS]
    return len(login_attempts[ip]) >= LOGIN_ATTEMPT_LIMIT

def record_failed_login(ip: str):
    login_attempts[ip].append(time.time())

def check_auth(username: str, password: str) -> bool:
    u_ok = secrets.compare_digest(username.encode(), PANEL_USER.encode())
    p_ok = secrets.compare_digest(password.encode(), PANEL_PASS.encode())
    return u_ok and p_ok

def authenticate(reason="Giriş Yetkiniz Yok"):
    return Response(f"Siber Kalkan: {reason}", 401,
                    {"WWW-Authenticate": 'Basic realm="Siber Kalkan Panel"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        if ALLOWED_PANEL_NETWORKS:
            if not any(client_ip.startswith(net) for net in ALLOWED_PANEL_NETWORKS):
                return Response("Siber Kalkan: Bu ağdan erişim yasaktır.", 403)
        if is_login_locked(client_ip):
            return Response("Çok fazla başarısız giriş. 5 dakika bekleyin.", 429)
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            record_failed_login(client_ip)
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════════
# 14. FLASK UYGULAMASI
# ══════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]           = "no-referrer"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self';"
    )
    return response

# DDoS koruması: Panel'e gelen istekleri de izle
@app.before_request
def panel_ddos_guard():
    ip = request.remote_addr
    if ip and ddos_check(ip):
        logger.warning(f"⚡ [PANEL DDoS] {ip} panele DDoS yapıyor, engelleniyor.")
        Thread(target=execute_ban, args=(ip, "Panel DDoS"), daemon=True).start()
        return Response("Engellendi.", 429)

# ══════════════════════════════════════════════════════════════════
# 15. HTML PANELİ
# ══════════════════════════════════════════════════════════════════

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Siber Kalkan v13.0 - Titan</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #020617; color: #f8fafc;
            margin: 0; padding: 20px;
        }
        .container { max-width: 1300px; margin: auto; }
        .stats-grid  { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-bottom: 20px; }
        .mini-grid   { display: grid; grid-template-columns: repeat(3,1fr); gap: 15px; margin-bottom: 20px; }
        .card {
            background: #1e293b; padding: 22px; border-radius: 15px;
            border: 1px solid #334155;
            box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5);
        }
        .big-number  { font-size: 3.5rem; font-weight: 800; color: #22c55e; line-height: 1; }
        .mini-number { font-size: 2rem;   font-weight: 700; color: #f59e0b; line-height: 1; }

        /* Canlı saat */
        #live-clock {
            font-family: 'Courier New', monospace;
            font-size: 2.2rem; font-weight: 800;
            color: #38bdf8; letter-spacing: .08em;
            text-shadow: 0 0 18px rgba(56,189,248,.45);
        }
        #live-date { font-size: .82rem; color: #64748b; margin-top: 4px; }
        .clock-dot {
            display: inline-block; width: 8px; height: 8px;
            background: #22c55e; border-radius: 50%; margin-right: 6px;
            animation: blink 1s step-start infinite;
        }
        @keyframes blink { 50% { opacity: 0; } }

        /* Tablo */
        table { width:100%; border-collapse:collapse; margin-top:15px; background:#0f172a; border-radius:10px; overflow:hidden; }
        th,td { text-align:left; padding:13px 15px; border-bottom:1px solid #1e293b; font-size:.9rem; }
        th    { background:#334155; color:#38bdf8; text-transform:uppercase; font-size:.75rem; }
        .tag  { display:inline-block; padding:3px 8px; border-radius:5px; font-size:.72rem; font-weight:600; }
        .tag-ssh    { background:#7c3aed22; color:#a78bfa; border:1px solid #7c3aed; }
        .tag-scan   { background:#0ea5e922; color:#38bdf8; border:1px solid #0ea5e9; }
        .tag-ddos   { background:#ef444422; color:#f87171; border:1px solid #ef4444; }
        .tag-other  { background:#64748b22; color:#94a3b8; border:1px solid #475569; }
        .tag-ipv6   { background:#10b98122; color:#34d399; border:1px solid #10b981; }
        .tag-ipv4   { background:#3b82f622; color:#93c5fd; border:1px solid #3b82f6; }
        .unban-btn  {
            background:#ef444422; color:#ef4444;
            border:1px solid #ef4444; padding:7px 13px;
            border-radius:8px; cursor:pointer; transition:.3s; font-weight:700; font-size:.8rem;
        }
        .unban-btn:hover  { background:#ef4444; color:#fff; }
        .status-badge {
            padding:5px 12px; border-radius:6px; font-size:.75rem;
            background:#22c55e22; color:#22c55e; border:1px solid #22c55e;
        }
        .fail2ban-box {
            background:#0f172a; border-radius:10px;
            padding:15px; font-family:monospace;
            font-size:.78rem; color:#94a3b8;
            white-space:pre-wrap; max-height:160px; overflow-y:auto;
            border:1px solid #1e293b;
        }
        .section-title { margin: 0 0 15px 0; color:#e2e8f0; font-size:1rem; }
    </style>
</head>
<body>
<div class="container">

    <!-- BAŞLIK -->
    <header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:28px;flex-wrap:wrap;gap:15px;">
        <div>
            <h1 style="color:#38bdf8;margin:0;">🛡️ Siber Kalkan
                <span style="font-size:.95rem;color:#94a3b8;">v13.0 Titan</span>
            </h1>
            <p style="margin:5px 0 0;color:#64748b;">Log: <code style="color:#fbbf24;">{{ log_path }}</code></p>
        </div>

        <!-- CANLI SAAT -->
        <div class="card" style="padding:16px 26px;min-width:200px;">
            <div id="live-clock">--:--:--</div>
            <div id="live-date">Yükleniyor...</div>
        </div>

        <div class="status-badge"><span class="clock-dot"></span>SİSTEM AKTİF</div>
    </header>

    <!-- ANA İSTATİSTİK KARTLARI -->
    <div class="stats-grid" style="margin-bottom:15px;">
        <div class="card">
            <h3 style="margin-top:0;color:#94a3b8;">Bugün Engellenen</h3>
            <div class="big-number">{{ total }}</div>
            <p style="color:#475569;margin-bottom:0;">Toplam Tehdit</p>
        </div>
        <div class="card">
            <canvas id="attackChart" height="110"></canvas>
        </div>
    </div>

    <!-- MİNİ KARTLAR -->
    <div class="mini-grid">
        <div class="card">
            <h4 style="margin-top:0;color:#94a3b8;font-size:.82rem;">SSH Brute-Force</h4>
            <div class="mini-number">{{ ssh_count }}</div>
        </div>
        <div class="card">
            <h4 style="margin-top:0;color:#94a3b8;font-size:.82rem;">Port Scan</h4>
            <div class="mini-number" style="color:#38bdf8;">{{ scan_count }}</div>
        </div>
        <div class="card">
            <h4 style="margin-top:0;color:#94a3b8;font-size:.82rem;">DDoS</h4>
            <div class="mini-number" style="color:#f87171;">{{ ddos_count }}</div>
        </div>
    </div>

    <!-- FAIL2BAN DURUM KARTI -->
    <div class="card" style="margin-bottom:20px;">
        <h3 class="section-title">⚙️ Fail2ban Jail Durumu — <code style="color:#fbbf24;">{{ f2b_jail }}</code></h3>
        <div class="fail2ban-box">{{ f2b_status }}</div>
    </div>

    <!-- BAN GEÇMİŞİ TABLOSU -->
    <div class="card">
        <h3 class="section-title">📋 Son Ban Kayıtları (Son 20)</h3>
        <table>
            <thead>
                <tr>
                    <th>Zaman</th>
                    <th>IP Adresi</th>
                    <th>Konum</th>
                    <th>Sebep</th>
                    <th>Protokol</th>
                    <th>Müdahale</th>
                </tr>
            </thead>
            <tbody>
            {% for ban in history %}
            <tr id="row-{{ loop.index }}">
                <td style="color:#94a3b8;font-size:.82rem;">{{ ban.time }}</td>
                <td><b style="color:#38bdf8;font-family:monospace;">{{ ban.ip }}</b></td>
                <td style="color:#cbd5e1;">{{ ban.loc }}</td>
                <td>
                    {% if 'SSH' in ban.reason %}
                        <span class="tag tag-ssh">SSH</span>
                    {% elif 'Scan' in ban.reason or 'scan' in ban.reason %}
                        <span class="tag tag-scan">PORT SCAN</span>
                    {% elif 'DDoS' in ban.reason or 'ddos' in ban.reason %}
                        <span class="tag tag-ddos">DDoS</span>
                    {% else %}
                        <span class="tag tag-other">{{ ban.reason }}</span>
                    {% endif %}
                </td>
                <td>
                    {% if ban.ip_ver == 'IPv6' %}
                        <span class="tag tag-ipv6">IPv6</span>
                    {% else %}
                        <span class="tag tag-ipv4">IPv4</span>
                    {% endif %}
                </td>
                <td>
                    <button class="unban-btn"
                        onclick="unbanIP('{{ ban.ip }}', 'row-{{ loop.index }}')">
                        Banı Kaldır
                    </button>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="6" style="text-align:center;color:#475569;padding:30px;">
                Henüz ban kaydı yok.
            </td></tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

</div>

<script>
    // ── CANLI SAAT ────────────────────────────────────────────────
    const TR_DAYS   = ['Pazar','Pazartesi','Salı','Çarşamba','Perşembe','Cuma','Cumartesi'];
    const TR_MONTHS = ['Ocak','Şubat','Mart','Nisan','Mayıs','Haziran',
                       'Temmuz','Ağustos','Eylül','Ekim','Kasım','Aralık'];
    function pad(n){ return String(n).padStart(2,'0'); }
    function tick(){
        const d = new Date();
        document.getElementById('live-clock').textContent =
            pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());
        document.getElementById('live-date').textContent =
            TR_DAYS[d.getDay()]+', '+pad(d.getDate())+' '+TR_MONTHS[d.getMonth()]+' '+d.getFullYear();
    }
    tick(); setInterval(tick, 1000);

    // ── UNBAN ─────────────────────────────────────────────────────
    function unbanIP(ip, rowId){
        // Client-side IP format kontrolü (IPv4 + IPv6)
        const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6 = /^[0-9a-fA-F:]+$/;
        if(!ipv4.test(ip) && !ipv6.test(ip)){
            alert('Geçersiz IP adresi!'); return;
        }
        fetch('/unban',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ip})
        }).then(r=>{
            if(r.ok){
                const row = document.getElementById(rowId);
                row.style.transition='0.5s'; row.style.opacity='0.25';
                const btn = row.querySelector('button');
                btn.innerText='TAHLİYE EDİLDİ'; btn.disabled=true;
            } else { alert('Unban başarısız!'); }
        }).catch(()=>alert('Sunucuya bağlanılamadı.'));
    }

    // ── SALDIRI GRAFİĞİ ──────────────────────────────────────────
    new Chart(document.getElementById('attackChart').getContext('2d'),{
        type:'line',
        data:{
            labels: Array.from({length:24},(_,i)=>i+':00'),
            datasets:[{
                label:'Saatlik Saldırı',
                data: {{ hourly_data }},
                borderColor:'#22c55e',
                backgroundColor:'rgba(34,197,94,0.1)',
                borderWidth:3, tension:0.4, fill:true,
                pointRadius:4, pointBackgroundColor:'#22c55e'
            }]
        },
        options:{
            scales:{
                y:{ beginAtZero:true, grid:{color:'#1e293b'} },
                x:{ grid:{display:false} }
            },
            plugins:{ legend:{display:false} }
        }
    });

    // Sayfa verilerini 15 saniyede bir yenile
    setTimeout(()=>location.reload(), 15000);
</script>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════════════
# 16. FLASK ROTALAR
# ══════════════════════════════════════════════════════════════════

@app.route("/")
@requires_auth
def index():
    # Her veri çekme adımı ayrı ayrı korunuyor — biri patlarsa sayfa yine açılır
    try:
        history = db_get_recent_bans(20)
    except Exception as e:
        logger.error(f"index/history hatası: {e}")
        history = []

    try:
        total = db_get_today_total()
    except Exception as e:
        logger.error(f"index/total hatası: {e}")
        total = 0

    try:
        hourly = db_get_hourly_today()
    except Exception as e:
        logger.error(f"index/hourly hatası: {e}")
        hourly = [0] * 24

    # fail2ban_status artık exception fırlatmıyor ama yine de sarıyoruz
    try:
        f2b = fail2ban_status(FAIL2BAN_SSH_JAIL)
    except Exception as e:
        logger.error(f"index/fail2ban hatası: {e}")
        f2b = {"output": f"Hata: {e}", "ok": False}

    ssh_count  = sum(1 for b in history if "SSH"  in b.get("reason", ""))
    scan_count = sum(1 for b in history if "Scan" in b.get("reason", "") or "scan" in b.get("reason", ""))
    ddos_count = sum(1 for b in history if "DDoS" in b.get("reason", "") or "ddos" in b.get("reason", ""))

    return render_template_string(
        HTML_TEMPLATE,
        history     = history,
        total       = total,
        hourly_data = hourly,
        log_path    = LOG_FILE,
        f2b_status  = f2b["output"] if f2b["ok"] else f2b["output"],
        f2b_jail    = FAIL2BAN_SSH_JAIL,
        ssh_count   = ssh_count,
        scan_count  = scan_count,
        ddos_count  = ddos_count,
    )

@app.route("/unban", methods=["POST"])
@requires_auth
def unban_route():
    data = request.get_json(silent=True)
    ip   = (data or {}).get("ip", "").strip()

    if not ip or not is_valid_ip(ip):
        return jsonify({"status": "error", "message": "Geçersiz IP"}), 400

    norm = normalize_ip(ip)
    if norm in [normalize_ip(t) for t in TRUSTED_IPS]:
        return jsonify({"status": "error", "message": "Korumalı IP"}), 403

    execute_unban(norm)
    return jsonify({"status": "success"})

@app.route("/api/stats")
@requires_auth
def api_stats():
    """JSON istatistik endpoint'i — harici araçlar için."""
    return jsonify({
        "total_today": db_get_today_total(),
        "hourly":      db_get_hourly_today(),
        "recent_bans": db_get_recent_bans(10),
        "fail2ban":    fail2ban_status(FAIL2BAN_SSH_JAIL),
    })

# ══════════════════════════════════════════════════════════════════
# 17. ÇALIŞTIRMA
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()

    # Tüm monitörleri arka planda başlat
    Thread(target=monitor_logs,       daemon=True, name="SSH-Monitor").start()
    Thread(target=monitor_ufw_blocks, daemon=True, name="UFW-Monitor").start()

    logger.info("🛡️  Siber Kalkan v13.0 Titan başlatıldı.")
    logger.info(f"📁 Log dizini: {LOG_DIR}")
    logger.info(f"🌐 Panel: http://0.0.0.0:5000  (kullanıcı: {PANEL_USER})")

    # Flask'ı ana thread'de çalıştır
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
