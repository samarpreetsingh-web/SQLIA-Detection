# monitor/interceptor.py

def intercept_query(query):
    print(f"[MONITOR] Intercepted SQL Query: {query}")
    return query