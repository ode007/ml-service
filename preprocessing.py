import re
from urllib.parse import urlparse, parse_qs, unquote
from scipy.sparse import hstack, csr_matrix

def normalize_text_for_ml(text):
    """
    Normalisasi spasi dan token untuk Machine Learning (TF-IDF & RegEx Features):
    1. Memisahkan keyword SQL/XSS yang menempel dengan angka/simbol (misal: or1 -> or 1)
    2. Memberi spasi pada simbol kutip dan operator agar token TF-IDF dan regex \b bekerja optimal.
    """
    if not text:
        return ""
    t = re.sub(r"(?i)\b(or|and)(\d+)", r" \1 \2 ", text)
    t = re.sub(r"(['\"=])", r" \1 ", t)
    return " ".join(t.split())

def clean_url(url):
    """
    Normalisasi URL dari format absolut (http://...) ke relative URI path
    dan melakukan URL-decode (%3C -> <, %27 -> ', dll) agar sesuai dengan
    format access log pada dataset pelatihan.
    """
    if not url:
        return ""
    # Lakukan URL-decode (menangani single/double URL encoding dari browser)
    try:
        url = unquote(unquote(url))
    except Exception:
        pass

    if url.startswith("http://") or url.startswith("https://"):
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{path}{query}"
    return url

def extract_query_payload(url):
    """
    Mengekstrak nilai parameter query murni untuk inspeksi fokus payload.
    Misal: /search?q=<script>alert(1)</script> -> <script>alert(1)</script>
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            return " ".join([item for sublist in qs.values() for item in sublist])
    except Exception:
        pass
    return ""

def extra_features(text):
    """
    Ekstraksi 16 fitur manual sesuai spesifikasi notebook Model_Training_Hasil.ipynb
    """
    text_lower = text.lower()
    return [
        # --- Fitur Umum & SQLi ---
        len(text),
        text.count("'") + text.count('"'),
        text.count("="),
        len(re.findall(r"\bOR\b", text, re.IGNORECASE)),
        len(re.findall(r"\bAND\b", text, re.IGNORECASE)),
        len(re.findall(r"\bUNION\b", text, re.IGNORECASE)),
        len(re.findall(r"\bSELECT\b", text, re.IGNORECASE)),
        text.count("--") + text.count("#"),

        # --- Fitur Tambahan untuk XSS ---
        text.count("<") + text.count(">"),
        text_lower.count("script"),
        text_lower.count("alert"),
        text_lower.count("onload") + text_lower.count("onerror"),

        # --- Fitur Tambahan untuk Path Traversal ---
        text.count("../") + text.count("..\\") + text.count("..%2f") + text_lower.count("%2e%2e"),
        text.count("/") + text.count("\\"),
        text_lower.count("etc/passwd"),
        text_lower.count(".exe") + text_lower.count(".ini")
    ]

def preprocess_input(data, vectorizer):
    """
    Memproses dictionary data {url, referrer, user_agent} menjadi fitur sparse matrix
    berdimensi sesuai input model Random Forest (2347 fitur).
    """
    raw_url = data.get("url", "") or ""
    url = normalize_text_for_ml(clean_url(raw_url))
    referrer = data.get("referrer", "") or ""
    user_agent = data.get("user_agent", "") or ""

    combined = f"{url} {referrer} {user_agent}".strip()
    if not combined:
        combined = "normal"

    text_vec = vectorizer.transform([combined])
    ef = extra_features(combined)
    ef_sparse = csr_matrix([ef])

    final_input = hstack([text_vec, ef_sparse])
    return final_input, combined