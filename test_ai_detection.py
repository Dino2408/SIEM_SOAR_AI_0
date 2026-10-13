import requests
import json

AI_ENGINE_URL = "http://localhost:8001"

def test_attack_detection():
    print("--- Khởi chạy kiểm tra khả năng phát hiện tấn công bằng AI ---")
    
    # 1. Log mô phỏng SQL Injection
    sql_injection_log = {
        "raw_log": '192.168.1.100 - - [10/Oct/2026:13:55:36 -0700] "GET /login?user=admin\' OR \'1\'=\'1&password= HTTP/1.1" 200 2326'
    }
    
    print("\n[+] Gửi log SQL Injection đến AI Engine (phân loại)...")
    response = requests.post(f"{AI_ENGINE_URL}/classify/log", json=sql_injection_log)
    if response.status_code == 200:
        parsed_event = response.json()
        print("Kết quả phân loại (NLP Classifier):")
        print(json.dumps(parsed_event, indent=2, ensure_ascii=False))
        
        # 2. Phân tích sự kiện bằng AI (Event Analyzer)
        print("\n[+] Gửi sự kiện đã phân loại để phân tích mức độ nghiêm trọng và MITRE ATT&CK...")
        analysis_res = requests.post(f"{AI_ENGINE_URL}/analyze/event", json=parsed_event)
        if analysis_res.status_code == 200:
            print("Kết quả phân tích sự kiện (Event Analyzer):")
            print(json.dumps(analysis_res.json(), indent=2, ensure_ascii=False))
        else:
            print("Lỗi phân tích:", analysis_res.text)
    else:
        print("Lỗi phân loại:", response.text)

if __name__ == "__main__":
    test_attack_detection()
