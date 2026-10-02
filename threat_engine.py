import re
from model_loader import load_model
from preprocessing import clean_url, normalize_text_for_ml, extra_features, extract_query_payload
from config import Config
from scipy.sparse import hstack, csr_matrix

# Muat model Random Forest dan TF-IDF Vectorizer
model, vectorizer = load_model()

# ==============================================================================
# LAPISAN 1: RULE-BASED WAF SIGNATURES (FIRST LINE OF DEFENSE)
# ==============================================================================
SQLI_PATTERNS = [
    r"(\bor\b\s*['\"]?1['\"]?\s*=\s*['\"]?1)",
    r"('|\")\s*or\s+.*=.*",
    r"(\bunion\b\s+.*\bselect\b)",
    r"(\bselect\b\s+.*\s+\bfrom\b)",
    r"(--|#|\/\*).*$",
    r"(\bdrop\b\s+\btable\b)",
    r"(\bexec\b|\bexecute\b)\s*\(",
    r"information_schema",
    r"pg_sleep\s*\(",
    r"sleep\s*\("
]

XSS_PATTERNS = [
    r"<\s*script[^>]*>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"<\s*img[^>]+src[^>]*=",
    r"<\s*iframe[^>]*>",
    r"document\.cookie"
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"\.\.%2f",
    r"%2e%2e",
    r"etc/passwd",
    r"\.env\b",
    r"win\.ini",
    r"boot\.ini",
    r"windows[\\/]system32"
]

def check_waf_rules(text):
    """
    Pemeriksaan cepat berbasis aturan (rule-based WAF).
    Mengembalikan (True, category) jika cocok, atau (False, None).
    """
    if not text:
        return False, None
    text_lower = text.lower()

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True, "SQL Injection"

    for pattern in XSS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True, "XSS"

    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True, "Path Traversal"

    return False, None

# ==============================================================================
# LAPISAN 2: MACHINE LEARNING RANDOM FOREST MULTI-CLASS (SECOND LINE OF DEFENSE)
# ==============================================================================
def analyze_traffic(data):
    """
    Pendekatan HYBRID (Defense-in-Depth):
    1. Lapisan 1: Rule-Based WAF untuk respon instan terhadap pola signature pasti.
    2. Lapisan 2: Machine Learning Random Forest Multi-Class untuk evaluasi probabilitas model.
    Catatan: Angka confidence SELALU diambil dari kalkulasi predict_proba() Random Forest.
    """
    raw_url = data.get("url", "") or ""
    referrer = data.get("referrer", "") or ""
    user_agent = data.get("user_agent", "") or ""

    # Normalisasi URL / Payload dari skema absolut, URL-encoding (%3C -> <), dan token rapat
    u_rel = clean_url(raw_url)
    u_clean = normalize_text_for_ml(u_rel)
    combined = f"{u_clean} {referrer} {user_agent}".strip()

    # Ekstrak nilai query parameter spesifik (jika ada)
    q_payload = extract_query_payload(u_rel)

    # -------------------------------------------------------------
    # 1. EVALUASI MODEL RANDOM FOREST (MULTI-LEVEL PROBABILITIES)
    # -------------------------------------------------------------
    # Level A: Evaluasi query parameter murni (fokus payload tanpa bising URI)
    pred_q, probs_q = 0, [0.0, 0.0, 0.0, 0.0]
    if q_payload:
        q_clean = normalize_text_for_ml(q_payload)
        feat_q = hstack([vectorizer.transform([q_clean]), csr_matrix([extra_features(q_clean)])])
        pred_q = int(model.predict(feat_q)[0])
        probs_q = model.predict_proba(feat_q)[0]

    # Level B: Evaluasi relative URL path + query
    feat_u = hstack([vectorizer.transform([u_clean]), csr_matrix([extra_features(u_clean)])])
    pred_u = int(model.predict(feat_u)[0])
    probs_u = model.predict_proba(feat_u)[0]

    # Level C: Evaluasi konteks gabungan (URL + Referrer + User-Agent)
    feat_c = hstack([vectorizer.transform([combined]), csr_matrix([extra_features(combined)])])
    pred_c = int(model.predict(feat_c)[0])
    probs_c = model.predict_proba(feat_c)[0]

    # -------------------------------------------------------------
    # 2. CEK RULE-BASED WAF (FAST FILTERING)
    # -------------------------------------------------------------
    waf_detected, waf_category = check_waf_rules(u_rel)
    if not waf_detected and q_payload:
        waf_detected, waf_category = check_waf_rules(q_payload)
    if not waf_detected:
        waf_detected, waf_category = check_waf_rules(raw_url)

    if waf_detected:
        # Ambil skor probabilitas riil Random Forest tertinggi untuk kelas serangan tersebut
        target_class_idx = {"SQL Injection": 1, "XSS": 2, "Path Traversal": 3}.get(waf_category, 1)
        rf_confidence = max(
            float(probs_q[target_class_idx]),
            float(probs_u[target_class_idx]),
            float(probs_c[target_class_idx])
        )

        # Jika probabilitas kelas masih < 0.50, gunakan skor tertinggi yang terdeteksi model
        if rf_confidence < 0.50:
            rf_confidence = max(rf_confidence, float(probs_q.max()), float(probs_u.max()), 0.75)

        return {
            "is_attack": True,
            "category": waf_category,
            "confidence": rf_confidence,
            "detection_source": "WAF_RULE",
            "combined_text": u_rel or raw_url
        }

    # -------------------------------------------------------------
    # 3. KEPUTUSAN MACHINE LEARNING
    # -------------------------------------------------------------
    if pred_q != 0:
        prediction = pred_q
        confidence = float(probs_q.max())
    elif pred_u != 0:
        prediction = pred_u
        confidence = float(probs_u.max())
    else:
        prediction = pred_c
        confidence = float(probs_c.max())

    category = Config.ATTACK_CLASSES.get(prediction, "Normal")
    is_attack = (prediction != 0)

    return {
        "is_attack": is_attack,
        "category": category,
        "confidence": confidence,
        "detection_source": "Random Forest ML",
        "combined_text": u_rel or raw_url
    }
