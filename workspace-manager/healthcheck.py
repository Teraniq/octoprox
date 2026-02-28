import http.client
import sys

try:
    conn = http.client.HTTPConnection('127.0.0.1', 8000, timeout=5)
    conn.request('GET', '/health')
    status = conn.getresponse().status
    conn.close()
    sys.exit(0 if status == 200 else 1)
except Exception:
    sys.exit(1)
