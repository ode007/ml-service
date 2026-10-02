import time
import datetime
from flask import Blueprint, request, jsonify, current_app
from threat_engine import analyze_traffic
from database import log_incident, log_normal_traffic, get_metrics, get_trend_data, get_recent_incidents, clear_all_logs, block_ip, unblock_ip, is_ip_blocked, get_blocked_ips
from telegram_service import send_alert_async

api_bp = Blueprint('api', __name__)

@api_bp.route('/predict', methods=['POST'])
def predict():
    """
    Endpoint utama intersepsi traffic dari Laravel SIAKAD Middleware.
    Menganalisis request untuk mendeteksi ancaman (Normal, SQLi, XSS, Path Traversal).
    """
    start_time = time.time()
    try:
        req_json = request.get_json(silent=True) or {}
        # Menangani format bersarang {"data": {...}} atau format langsung {...}
        data = req_json.get('data', req_json)

        if not data:
            return jsonify({"error": "No input payload provided"}), 400

        # Ambil metadata request pengirim
        client_ip = (
            req_json.get('ip_address') 
            or (data.get('ip_address') if isinstance(data, dict) else None)
            or (request.headers.get('X-Forwarded-For', '').split(',')[0].strip() if request.headers.get('X-Forwarded-For') else None)
            or request.remote_addr 
            or "127.0.0.1"
        )
        http_method = req_json.get('method') or (data.get('method') if isinstance(data, dict) else None) or request.method or "GET"
        url = data.get('url', '')
        user_agent = data.get('user_agent', request.headers.get('User-Agent', ''))

        # 0. CEK IP BLACKLIST (Intersepsi Cepat jika IP Telah Diblokir Permanen)
        if is_ip_blocked(client_ip):
            latency_ms = round((time.time() - start_time) * 1000, 2)
            log_incident(
                ip_address=client_ip,
                method=http_method,
                url=url,
                payload="[DROPPED] IP Terdaftar dalam Blacklist",
                user_agent=user_agent,
                category="IP Blacklist",
                confidence=1.0,
                action="block",
                detection_source="IP_BLACKLIST"
            )
            return jsonify({
                "status": "threat",
                "result": "attack",
                "category": "IP Blacklist",
                "action": "block",
                "confidence": 1.0,
                "source": "IP_BLACKLIST",
                "latency_ms": latency_ms
            }), 200

        # Analisis ancaman via Hybrid Engine (WAF Rules + Multi-class RF)
        analysis = analyze_traffic(data)
        latency_ms = round((time.time() - start_time) * 1000, 2)

        # Simpan latensi terakhir di app config untuk indikator health dashboard
        current_app.config['LAST_LATENCY_MS'] = latency_ms

        if analysis['is_attack']:
            category = analysis['category']
            confidence = analysis['confidence']
            detection_source = analysis['detection_source']
            action = "block"

            # 1. Catat insiden ke SQLite
            log_incident(
                ip_address=client_ip,
                method=http_method,
                url=url,
                payload=analysis.get('combined_text', url),
                user_agent=user_agent,
                category=category,
                confidence=confidence,
                action=action,
                detection_source=detection_source
            )

            # 2. Kirim notifikasi Telegram asinkron
            send_alert_async(
                ip_address=client_ip,
                category=category,
                url=url,
                payload=analysis.get('combined_text', url),
                confidence=confidence,
                action=action
            )

            # 3. Kembalikan respon ancaman ke Laravel SIAKAD
            return jsonify({
                "status": "threat",
                "result": "attack",
                "category": category,
                "action": action,
                "confidence": round(confidence, 4),
                "source": detection_source,
                "latency_ms": latency_ms
            }), 200

        else:
            # Request normal
            log_normal_traffic()
            return jsonify({
                "status": "safe",
                "result": "normal",
                "category": "Normal",
                "action": "allow",
                "confidence": round(analysis['confidence'], 4),
                "source": analysis['detection_source'],
                "latency_ms": latency_ms
            }), 200

    except Exception as e:
        latency_ms = round((time.time() - start_time) * 1000, 2)
        return jsonify({
            "error": str(e),
            "status": "error",
            "latency_ms": latency_ms
        }), 500

@api_bp.route('/api/metrics', methods=['GET'])
def metrics():
    """
    Endpoint polling AJAX untuk dashboard SOC.
    Mengembalikan ringkasan statistik terkini, status engine, dan data tren grafik.
    Default: reset harian (Hari ini).
    """
    date = request.args.get('date', None)
    stats = get_metrics(date=date)
    trend = get_trend_data(limit_points=1440, date=date)

    # Hitung uptime engine
    start_time = current_app.config.get('START_TIME', datetime.datetime.now())
    uptime_seconds = int((datetime.datetime.now() - start_time).total_seconds())
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours}h {minutes}m {seconds}s"

    last_latency = current_app.config.get('LAST_LATENCY_MS', 1.25)

    return jsonify({
        "metrics": stats,
        "trend": trend,
        "engine": {
            "status": "Online",
            "uptime": uptime_str,
            "latency_ms": last_latency,
            "model_version": "RandomForest-Multiclass-v2"
        }
    })

@api_bp.route('/api/incidents', methods=['GET'])
def incidents():
    """
    Endpoint untuk mengambil daftar log insiden dengan paginasi 10 data, filter tanggal, kategori, dan pencarian.
    """
    category = request.args.get('category', 'all')
    search = request.args.get('search', '').strip()
    date = request.args.get('date', None)
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))

    data = get_recent_incidents(limit=limit, page=page, category=category, search=search, date=date)
    return jsonify(data)

@api_bp.route('/api/incidents/clear', methods=['POST'])
def clear_incidents():
    """
    Endpoint untuk mereset seluruh data log insiden dan statistik traffic.
    """
    clear_all_logs()
    return jsonify({"status": "success", "message": "Semua log insiden dan metrik berhasil dibersihkan."})

@api_bp.route('/api/blocked-ips', methods=['GET'])
def list_blocked_ips():
    """Mengambil daftar seluruh IP yang diblokir."""
    data = get_blocked_ips()
    return jsonify({"blocked_ips": data, "total": len(data)})

@api_bp.route('/api/blocked-ips', methods=['POST'])
def add_blocked_ip():
    """Memblokir IP baru secara manual atau dari pop-up insiden."""
    req_data = request.get_json(silent=True) or {}
    ip = req_data.get('ip_address', '').strip()
    reason = req_data.get('reason', 'Manual Block / Threat Detected').strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP address harus diisi."}), 400
    success = block_ip(ip, reason)
    return jsonify({"status": "success" if success else "error", "ip_address": ip})

@api_bp.route('/api/blocked-ips/unblock', methods=['POST'])
def remove_blocked_ip():
    """Membuka blokir IP."""
    req_data = request.get_json(silent=True) or {}
    ip = req_data.get('ip_address', '').strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP address harus diisi."}), 400
    success = unblock_ip(ip)
    return jsonify({"status": "success" if success else "error", "ip_address": ip})

@api_bp.route('/api/blocked-ips/check', methods=['GET'])
def check_blocked_ip():
    """Memeriksa status blokir suatu IP."""
    ip = request.args.get('ip', '').strip()
    return jsonify({"ip_address": ip, "is_blocked": is_ip_blocked(ip)})



