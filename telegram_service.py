import threading
import json
import html
import urllib.request
import urllib.parse
from config import Config

def _send_telegram_http(message_text):
    """
    Fungsi internal untuk mengirim request HTTP POST ke Telegram Bot API.
    """
    token = Config.TELEGRAM_BOT_TOKEN
    chat_id = Config.TELEGRAM_CHAT_ID

    if not token or not chat_id:
        print("[Telegram Alert] Bot Token atau Chat ID belum dikonfigurasi. Alert dilewati.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message_text,
        "parse_mode": "HTML"
    }

    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                print("[Telegram Alert] Notifikasi berhasil terkirim.")
            else:
                print(f"[Telegram Alert] Gagal mengirim: HTTP {response.status}")
    except Exception as e:
        print(f"[Telegram Alert] Error koneksi Telegram: {e}")

def send_alert_async(ip_address, category, url, payload, confidence, action="BLOCKED"):
    """
    Memicu pengiriman notifikasi Telegram di background thread secara asinkron
    sehingga tidak membebani waktu respons API.
    Hanya dikirim jika confidence serangan memenuhi ambang batas minimum (>= 60%).
    """
    if confidence < Config.TELEGRAM_MIN_CONFIDENCE:
        print(f"[Telegram Alert] Dilewati: Confidence ({confidence * 100:.1f}%) di bawah ambang batas minimum ({Config.TELEGRAM_MIN_CONFIDENCE * 100:.1f}%).")
        return

    # Bersihkan payload agar tidak terlalu panjang jika di Telegram
    truncated_payload = (payload[:150] + "...") if payload and len(payload) > 150 else (payload or "N/A")

    safe_category = html.escape(str(category))
    safe_url = html.escape(str(url))
    safe_ip = html.escape(str(ip_address))
    safe_payload = html.escape(str(truncated_payload))
    safe_action = html.escape(str(action.upper()))

    message = (
        f"🚨 <b>SOC ALERT: Threat Detected!</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🛡️ <b>Attack Type:</b> <code>{safe_category}</code>\n"
        f"🎯 <b>Target URL:</b> <code>{safe_url}</code>\n"
        f"🌐 <b>Attacker IP:</b> <code>{safe_ip}</code>\n"
        f"💥 <b>Payload:</b> <code>{safe_payload}</code>\n"
        f"📊 <b>Confidence:</b> <code>{confidence * 100:.1f}%</code>\n"
        f"⚡ <b>Action Taken:</b> <code>{safe_action}</code>\n"
        f"🕒 <b>Status:</b> Intercepted &amp; Logged\n"
        f"━━━━━━━━━━━━━━━━━━"
    )

    thread = threading.Thread(target=_send_telegram_http, args=(message,), daemon=True)
    thread.start()

