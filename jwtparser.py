#!/usr/bin/env python3

import sys
import re
import base64
import json
from datetime import datetime

# Санитизация входных данных от мусора, скрипт сам удаляет лишнее и определяет токен по символам и блокам, раздёленных точками "."
# Пример: "   Authorization:   Bearer    <token>"
def sanitization(raw_token: str):
    match = re.search(r"([a-zA-Z0-9_-]+\.){2}[a-zA-Z0-9_-]*", raw_token)

    if match:
        return match.group()
    else:
        print("[!] Токен не найден.")
        sys.exit(1)

def decode(part: str):
    part += "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part)

def parse(token: str):
    raw_header, raw_payload, signature = token.split(".")
    try:
        header = json.loads(decode(raw_header))
        payload = json.loads(decode(raw_payload))
    except Exception as e:
        print(f"[!] Невалидный JSON/Base64 в токене")
        sys.exit(1)

    print(f"Decoded header:\n{json.dumps(header, indent=4)}")
    print(f"Decoded payload:\n{json.dumps(payload, indent=4)}")

    time_labels = {
        "exp": "Истекает (Expiration)",
        "iat": "Создан (Issued At)",
        "nbf": "Не активен до (Not Before)"
    }

    for field, labels in time_labels.items():
        val = payload.get(field)
        if val:
            date = datetime.fromtimestamp(val)
            print(f"[+] {labels}: {date}")

    print(f"Signature:\n{signature}")

    # Работа с подписью: Определяет размер подписи (байт/бит) и HEX
    # Размер подписи указывает на реальный криптографический алгоритм и длину ключа
    # HEX отображает сырые байты, что помогает найти тестовые заглушки (нули/паттерны) или подготовить хэш для брутфорса
    try:
        if signature == "":
            print("[!] Отсутствует подпись (Unsigned / None)")
        else:
            sig_bytes = decode(signature)
            print(f"[+] Размер подписи: {len(sig_bytes)} байт ({len(sig_bytes) * 8} бит)")
            print(f"[+] HEX: {sig_bytes.hex()}")
    except Exception as e:
        print(f"[!] Не удалось разобрать подпись: {e}")

    return header, payload, signature

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[!] Ошибка. Использование: python jwtparser.py <token>")
        sys.exit(1)

    safe_token = sanitization(sys.argv[1])
    parse(safe_token)