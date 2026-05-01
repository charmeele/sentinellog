import re
import os
from datetime import datetime

# Паттерны для обнаружения типичных атак
SIGNATURES = {
    "SQL Injection": r"UNION\s+SELECT|INSERT\s+INTO|UPDATE\s+.*SET|DROP\s+TABLE|' OR '1'='1",
    "XSS Attack": r"<script>|alert\(|onerror=|document\.cookie",
    "Path Traversal": r"\.\.\/\.\.\/|etc\/passwd|boot\.ini",
    "Brute Force Attempt": r"POST\s+.*\/login|401\s+Unauthorized"
}

def analyze_logs(log_file):
    """Анализирует лог-файл на наличие вредоносных сигнатур."""
    findings = []
    
    if not os.path.exists(log_file):
        print(f"[-] Файл {log_file} не найден.")
        return None

    print(f"[*] Начинаю анализ файла: {log_file}")
    print("-" * 50)

    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            for attack_type, pattern in SIGNATURES.items():
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line": line_num,
                        "type": attack_type,
                        "content": line.strip()
                    })
    
    return findings

def generate_report(findings):
    """Выводит результаты анализа в консоль."""
    if not findings:
        print("[+] Подозрительная активность не обнаружена.")
        return

    print(f"[!] Обнаружено {len(findings)} подозрительных событий:\n")
    
    for item in findings:
        print(f"Строка {item['line']} | Тип: {item['type']}")
        print(f"Данные: {item['content']}")
        print("-" * 30)

if __name__ == "__main__":
    # Для теста создадим временный файл с "плохими" логами, если его нет
    test_log = "access.log"
    if not os.path.exists(test_log):
        with open(test_log, "w") as f:
            f.write("127.0.0.1 - - [01/May/2026] \"GET /index.php?id=1' OR '1'='1\" 200\n")
            f.write("192.168.1.1 - - [01/May/2026] \"GET /search?q=<script>alert(1)</script>\" 200\n")
            f.write("10.0.0.5 - - [01/May/2026] \"GET /../../etc/passwd\" 404\n")
            f.write("172.16.0.1 - - [01/May/2026] \"POST /login\" 401\n")

    results = analyze_logs(test_log)
    if results is not None:
        generate_report(results)
