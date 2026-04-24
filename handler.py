# response/handler.py

def handle_query(is_malicious, query):
    if is_malicious:
        print(f"[RESPONSE] Query BLOCKED: {query}")
        return "BLOCKED"
    else:
        print(f"[RESPONSE] Query ALLOWED")
        return "ALLOWED"
    