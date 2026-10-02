import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'rf_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'tfidf.pkl')

def load_model():
    """
    Memuat model Random Forest dan TF-IDF Vectorizer dari disk.
    """
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return model, vectorizer