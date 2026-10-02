import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Muat file .env jika tersedia (tanpa dependensi eksternal)
env_file = os.path.join(BASE_DIR, '.env')
if os.path.exists(env_file):
    with open(env_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-secret-key-super-secure-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'soc_monitoring.db')
    
    # Telegram Bot Alert Configuration
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
    TELEGRAM_ALERT_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    TELEGRAM_MIN_CONFIDENCE = float(os.environ.get('TELEGRAM_MIN_CONFIDENCE', 0.60))  # Hanya kirim jika >= 60%
    
    # SOC Engine Settings
    ATTACK_CLASSES = {
        0: "Normal",
        1: "SQL Injection",
        2: "XSS",
        3: "Path Traversal"
    }

