import requests

data = {"event": {"source_ip": "192.168.1.50", "action": "failed_login", "username": "admin", "count": 25}}
try:
    response = requests.post("http://localhost:8001/analyze/event", json=data)
    print("Status:", response.status_code)
    print("Response:", response.json())
except Exception as e:
    print("Error:", e)
