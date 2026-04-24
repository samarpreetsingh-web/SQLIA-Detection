import numpy as np
import pandas as pd
import os
import joblib
import re

from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score

CSV_FILE_PATH = "data/Modified_SQL_Dataset.csv"
MODEL_PATH = "data/model.pkl"

THRESHOLD = 0.7
CONFIDENCE_MARGIN = 0.2

model_pipeline = None


def load_dataset():
    """Load and augment dataset with additional safe and known malicious queries."""
    if not os.path.exists(CSV_FILE_PATH):
        raise FileNotFoundError(f"Dataset file not found at: {CSV_FILE_PATH}")

    df = pd.read_csv(CSV_FILE_PATH)

    if 'Query' not in df.columns or 'Label' not in df.columns:
        raise ValueError("CSV must contain 'Query' and 'Label' columns")

    print("Original label distribution:")
    print(df['Label'].value_counts())

    # safe queries
    benign = [
        {'Query': '123', 'Label': 0},
        {'Query': '456', 'Label': 0},
        {'Query': 'hello', 'Label': 0},
        {'Query': 'banana', 'Label': 0},
        {'Query': 'SELECT name FROM fruits', 'Label': 0},
        {'Query': 'test', 'Label': 0},
        {'Query': '1=1', 'Label': 0},
        {'Query': 'admin123', 'Label': 0}
    ]
    df = pd.concat([df, pd.DataFrame(benign)], ignore_index=True)

    if not any(df['Query'] == "' OR 1'==1"):
        df = pd.concat([df, pd.DataFrame([{'Query': "' OR 1'==1", 'Label': 1}])], ignore_index=True)

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print("\n=== Dataset Statistics ===")
    print(f"Total Queries: {len(df)}")
    print(f"Safe Queries (Label=0): {sum(df['Label'] == 0)}")
    print(f"Malicious Queries (Label=1): {sum(df['Label'] == 1)}")
    print("==========================\n")

    return df

def load_or_train_model():
    """Load model from cache or train a new pipeline and save it."""
    global model_pipeline

    if os.path.exists(MODEL_PATH):
        print("Loading cached model pipeline...")
        model_pipeline = joblib.load(MODEL_PATH)
        return

    print("Training new model pipeline...")
    df = load_dataset()
    X, y = df["Query"], df["Label"]

    vectorizer = TfidfVectorizer(ngram_range=(1, 3), token_pattern=r"[A-Za-z_][A-Za-z0-9_]*")
    svd = TruncatedSVD(n_components=100, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
    model_pipeline = make_pipeline(vectorizer, svd, clf)

    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.3, random_state=42)
    model_pipeline.fit(X_train, y_train)
    y_pred = model_pipeline.predict(X_test)
    y_proba = model_pipeline.predict_proba(X_test)[:, 1]

    print("\n=== Model Evaluation ===")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"AUC: {roc_auc_score(y_test, y_proba):.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("========================\n")

    os.makedirs("data", exist_ok=True)
    joblib.dump(model_pipeline, MODEL_PATH)
    print("Model pipeline saved.")


def is_valid_input(query: str) -> bool:
    """Return False if the query is too short, empty, or non-alphabetic."""
    if not query.strip():
        return False
    if len(query.strip()) < 3:
        return False
    if not re.search(r"[a-zA-Z]", query):
        return False
    return True


def contains_suspicious_pattern(query: str) -> bool:
    """Detect known SQLi symbols or suspicious characters."""
    suspicious_tokens = ["--", "#", ";", "'", "\"", "/*", "*/", "xp_"]
    return any(token in query for token in suspicious_tokens)


def is_suspect_query_ml(query: str) -> bool:
    """
    Check if a query is likely malicious using the ML model and heuristic pattern detection.
    Returns True if suspect, False if safe.
    """
    global model_pipeline

    if not is_valid_input(query):
        print(f"[REJECTED] Invalid input: '{query}'")
        return False

    if model_pipeline is None:
        load_or_train_model()

    try:
        prob = model_pipeline.predict_proba([query])[0][1]
        print(f"Query: {query} => Malicious Probability: {prob:.4f}")

        if contains_suspicious_pattern(query):
            print("[HEURISTIC] Suspicious pattern detected — Blocking query.")
            return True

        if prob > THRESHOLD + CONFIDENCE_MARGIN:
            print("[RESPONSE] Query BLOCKED — High malicious score.")
            return True
        elif prob < THRESHOLD - CONFIDENCE_MARGIN:
            print("[RESPONSE] Query ALLOWED — Low malicious score.")
            return False
        else:
            print("[RESPONSE] Query ALLOWED — Borderline case.")
            return False
    except Exception as e:
        print(f"[ERROR] Classification failed for query: {query} — {e}")
        return False

if __name__ == "__main__":
    test_queries = [
        "SELECT * FROM users;",
        "' OR 1=1 --",
        "hello",
        "123",
        "' OR '1'='1",
        "banana",
        "DROP TABLE users;",
        "2023",
        "admin123",
        "DELETE FROM accounts WHERE id = 1",
        "'; DROP TABLE students; --",
        "1' OR '1' = '1",
        "this is a cat #",
        "this is safe text"
    ]

    for q in test_queries:
        result = is_suspect_query_ml(q)
        print(f"=> Final Verdict: {'SUSPECT' if result else 'SAFE'}\n")
