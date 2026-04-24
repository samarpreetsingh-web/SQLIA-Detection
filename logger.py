# logger/logger.py

import datetime
import os

LOG_FILE = "data/query_log.txt"

def log_event(query, status):
    os.makedirs("data", exist_ok=True)
    with open(LOG_FILE, "a") as log:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{timestamp} | {status} | {query}\n")