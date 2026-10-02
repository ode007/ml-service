import datetime
from flask import Flask
from config import Config
from database import init_db

# Blueprint imports
from routes.auth import auth_bp
from routes.api import api_bp
from routes.dashboard import dashboard_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Catat waktu mulai aplikasi untuk tracking uptime
    app.config['START_TIME'] = datetime.datetime.now()
    app.config['LAST_LATENCY_MS'] = 1.2

    # Inisialisasi Database SQLite & Seed Admin User
    with app.app_context():
        init_db()

    # Registrasi Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)

    return app

app = create_app()

if __name__ == '__main__':
    print("==================================================")
    print("🚀 SIAKAD SOC Threat Intelligence Dashboard MVP")
    print("🌐 Dashboard URL : http://127.0.0.1:5000")
    print("🔑 Default Login  : admin / admin123")
    print("🛡️  API Endpoint  : http://127.0.0.1:5000/predict")
    print("==================================================")
    app.run(host='0.0.0.0', port=5000, debug=True)