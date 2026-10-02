import sqlite3
import datetime
import math
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

def get_connection():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Inisialisasi tabel database SQLite dan seed user admin default jika belum ada.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Tabel Users untuk otentikasi Security Analyst
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabel Log Insiden Serangan
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            method TEXT,
            url TEXT,
            payload TEXT,
            user_agent TEXT,
            category TEXT,
            confidence REAL,
            action TEXT DEFAULT 'blocked',
            detection_source TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabel Metrik Lalu Lintas (Normal vs Attack)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            is_attack INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Normal',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabel IP Blacklist (Pemblokiran Permanen Akses)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            blocked_at DATETIME DEFAULT (datetime('now', 'localtime'))
        )
    ''')

    # Seed default user admin (admin / admin123)
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ('admin', hashed, 'admin')
        )

    conn.commit()
    conn.close()

def log_incident(ip_address, method, url, payload, user_agent, category, confidence, action="blocked", detection_source="Random Forest ML"):
    """
    Mencatat insiden serangan ke database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO incidents (ip_address, method, url, payload, user_agent, category, confidence, action, detection_source, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
    ''', (ip_address, method, url, payload, user_agent, category, float(confidence), action, detection_source))

    cursor.execute('''
        INSERT INTO traffic_stats (is_attack, category, timestamp)
        VALUES (1, ?, datetime('now', 'localtime'))
    ''', (category,))

    conn.commit()
    conn.close()

def log_normal_traffic():
    """
    Mencatat request normal ke traffic_stats untuk agregasi metrik.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO traffic_stats (is_attack, category, timestamp)
        VALUES (0, 'Normal', datetime('now', 'localtime'))
    ''')
    conn.commit()
    conn.close()

def get_metrics(date=None):
    """
    Menghitung metrik ringkasan (Total Request, Attack, Normal, Threat Ratio, Distribusi Kategori).
    Secara default dihitung untuk hari ini (reset saat berganti hari).
    """
    if date is None:
        date = datetime.date.today().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    where_clause = ""
    params = []
    if date != "all":
        where_clause = "WHERE DATE(timestamp) = ?"
        params = [date]

    cursor.execute(f"SELECT COUNT(*) FROM traffic_stats {where_clause}", params)
    total_requests = cursor.fetchone()[0]

    attack_where = f"{where_clause} AND is_attack = 1" if where_clause else "WHERE is_attack = 1"
    cursor.execute(f"SELECT COUNT(*) FROM traffic_stats {attack_where}", params)
    total_attacks = cursor.fetchone()[0]

    normal_where = f"{where_clause} AND is_attack = 0" if where_clause else "WHERE is_attack = 0"
    cursor.execute(f"SELECT COUNT(*) FROM traffic_stats {normal_where}", params)
    total_normal = cursor.fetchone()[0]

    threat_ratio = round((total_attacks / total_requests * 100), 2) if total_requests > 0 else 0.0

    # Distribusi kategori serangan
    cursor.execute(f'''
        SELECT category, COUNT(*) as count 
        FROM traffic_stats 
        {attack_where}
        GROUP BY category
    ''', params)
    category_counts = {row['category']: row['count'] for row in cursor.fetchall()}

    conn.close()

    return {
        "total_requests": total_requests,
        "total_attacks": total_attacks,
        "total_normal": total_normal,
        "threat_ratio": threat_ratio,
        "category_counts": category_counts
    }

def get_trend_data(limit_points=1440, date=None):
    """
    Mengambil data agregasi tren serangan per menit untuk Chart.js (reset per hari).
    Mendukung linimasa kontinu dari awal hari (00:00) hingga saat ini/akhir hari
    sehingga grafik dapat digeser (pan/drag) dan di-zoom (per menit hingga per jam).
    """
    if date is None:
        date = datetime.date.today().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    where_clause = ""
    params = []
    if date != "all":
        where_clause = "WHERE DATE(timestamp) = ?"
        params = [date]

    cursor.execute(f'''
        SELECT 
            strftime('%H:%M', timestamp) as minute_bucket,
            SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) as attacks,
            SUM(CASE WHEN is_attack = 0 THEN 1 ELSE 0 END) as normals
        FROM traffic_stats
        {where_clause}
        GROUP BY strftime('%H:%M', timestamp)
        ORDER BY strftime('%H:%M', timestamp) ASC
    ''', params)

    rows = cursor.fetchall()
    conn.close()

    # Petakan hasil query ke dictionary: minute_bucket -> (attacks, normals)
    data_map = {}
    for r in rows:
        data_map[r['minute_bucket']] = (r['attacks'], r['normals'])

    now_dt = datetime.datetime.now()
    now_hm = now_dt.strftime('%H:%M')
    today_iso = datetime.date.today().isoformat()

    if date == today_iso or date == "all":
        # Untuk hari ini: rentang kontinu dari 00:00 sampai menit sekarang (atau data terakhir)
        start_minute = "00:00"
        end_minute = max(now_hm, max(data_map.keys())) if data_map else now_hm
    else:
        # Untuk arsip tanggal lalu: rentang 24 jam penuh (00:00 sampai 23:59)
        start_minute = "00:00"
        end_minute = "23:59"

    try:
        cur_time = datetime.datetime.strptime(start_minute, "%H:%M")
        end_time = datetime.datetime.strptime(end_minute, "%H:%M")
    except Exception:
        cur_time = datetime.datetime.strptime("00:00", "%H:%M")
        end_time = datetime.datetime.strptime("23:59", "%H:%M")

    labels = []
    attacks = []
    normals = []

    step = datetime.timedelta(minutes=1)
    while cur_time <= end_time:
        m_str = cur_time.strftime('%H:%M')
        labels.append(m_str)
        atk, nrm = data_map.get(m_str, (0, 0))
        attacks.append(atk)
        normals.append(nrm)
        cur_time += step

    # Fallback aman jika labels kosong
    if not labels:
        labels = [now_hm]
        attacks = [0]
        normals = [0]

    return {
        "labels": labels,
        "attacks": attacks,
        "normals": normals
    }

def get_recent_incidents(limit=10, page=1, category=None, search=None, date=None):
    """
    Mengambil daftar riwayat insiden dengan paginasi (10 data) dan filter tanggal per hari.
    """
    if date is None:
        date = datetime.date.today().isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    query_where = "WHERE 1=1"
    params = []

    if date != "all":
        query_where += " AND DATE(timestamp) = ?"
        params.append(date)

    if category and category != "all":
        query_where += " AND category = ?"
        params.append(category)

    if search:
        query_where += " AND (ip_address LIKE ? OR url LIKE ? OR payload LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])

    # Hitung total records untuk pagination
    cursor.execute(f"SELECT COUNT(*) FROM incidents {query_where}", params)
    total_records = cursor.fetchone()[0]

    limit = max(1, int(limit))
    page = max(1, int(page))
    total_pages = max(1, math.ceil(total_records / limit))
    if page > total_pages and total_records > 0:
        page = total_pages
    offset = (page - 1) * limit

    # Query data paginasi
    data_query = f"SELECT * FROM incidents {query_where} ORDER BY id DESC LIMIT ? OFFSET ?"
    cursor.execute(data_query, params + [limit, offset])
    incidents = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "incidents": incidents,
        "total": total_records,
        "page": page,
        "limit": limit,
        "total_pages": total_pages
    }

def get_user_by_username(username):
    """
    Mencari data user berdasarkan username.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def clear_all_logs():
    """
    Menghapus seluruh log insiden dan statistik traffic untuk keperluan testing ulang.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM traffic_stats")
    conn.commit()
    conn.close()
    return True

def block_ip(ip_address, reason="Manual Block / Threat Detected"):
    """
    Menambahkan IP ke daftar hitam (blacklist) secara permanen.
    """
    if not ip_address:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips (ip_address, reason, blocked_at)
            VALUES (?, ?, datetime('now', 'localtime'))
        ''', (ip_address.strip(), reason))
        conn.commit()
        success = True
    except Exception as e:
        print(f"[DB Error block_ip]: {e}")
        success = False
    finally:
        conn.close()
    return success

def unblock_ip(ip_address):
    """
    Menghapus IP dari daftar hitam (lepas blokir).
    """
    if not ip_address:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address.strip(),))
        conn.commit()
        success = True
    except Exception as e:
        print(f"[DB Error unblock_ip]: {e}")
        success = False
    finally:
        conn.close()
    return success

def is_ip_blocked(ip_address):
    """
    Memeriksa apakah suatu IP terdaftar di tabel blacklist.
    """
    if not ip_address:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM blocked_ips WHERE ip_address = ?", (ip_address.strip(),))
    res = cursor.fetchone()
    conn.close()
    return bool(res)

def get_blocked_ips():
    """
    Mengambil seluruh daftar IP yang sedang diblokir.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


