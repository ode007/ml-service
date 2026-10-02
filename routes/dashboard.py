import datetime
from flask import Blueprint, render_template, session
from routes.auth import login_required
from database import get_metrics, get_recent_incidents, get_blocked_ips

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    """
    Halaman Utama SOC Threat Intelligence Dashboard.
    """
    user = session.get('user', {})
    today_str = datetime.date.today().isoformat()
    metrics_data = get_metrics(date=today_str)
    recent_incidents_data = get_recent_incidents(limit=10, page=1, date=today_str)
    blocked_ips_list = get_blocked_ips()
    return render_template(
        'dashboard.html',
        user=user,
        metrics=metrics_data,
        incidents=recent_incidents_data['incidents'],
        pagination=recent_incidents_data,
        blocked_ips=blocked_ips_list,
        today_date=today_str
    )

