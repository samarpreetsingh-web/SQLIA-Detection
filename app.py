# app.py
from interceptor import intercept_query
from detector import is_suspect_query_ml
from handler import handle_query
from logger import log_event

if __name__ == "__main__":
    print("=== SQL Injection Detection System Started ===\n")

    test_queries = [
        "SELECT * FROM users WHERE username='admin' AND password='admin'",
        "SELECT * FROM users WHERE username='' OR 1=1 --",
        "DROP TABLE students;",
        "INSERT INTO users (id, name) VALUES (1, 'hacker');",
        "UPDATE accounts SET balance = 10000 WHERE user='admin'",
        "' OR 1'=1"  # Add the problematic query
    ]

    for query in test_queries:
        intercepted = intercept_query(query)
        is_malicious = is_suspect_query_ml(intercepted)
        status = handle_query(is_malicious, intercepted)
        log_event(intercepted, status)

    print("\n=== Detection Completed. Check logs in /data/query_log.txt ===")