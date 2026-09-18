import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

# Підключення модуля shared
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import VARIANT_NUMBER


class ValidationError(Exception):
    """Власний виняток для помилок валідації пароля."""



# Параметри 5-го варіанту
SALT = str(VARIANT_NUMBER).zfill(5)  # "00005"
MIN_PASSWORD_LENGTH = 16

# Шляхи до файлів
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш sha3_256 для 5-го варіанту."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)."
        )

    salted_data = (password + salt).encode("utf-8")
    return hashlib.sha3_256(salted_data).hexdigest()


def log_event(func):
    """Декоратор для логування спроб входу в log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")
        result_status = "failure"
        result = False

        try:
            result = func(*args, **kwargs)
            if result:
                result_status = "success"
        except Exception:
            result_status = "failure"
            raise
        finally:
            os.makedirs(DATA_DIR, exist_ok=True)
            logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (OSError, json.JSONDecodeError):
                    logs = []

            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),# noqa: DTZ005
                "args": list(args),
                "kwargs": kwargs,
            }
            logs.append(log_entry)

            with open(LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

        return result

    return wrapper


def create_user(username: str, password: str) -> tuple:
    hash_val = generate_hash(password, SALT)
    return (username, hash_val)


def create_users(users_list: list):
    """Записує користувачів у CSV-базу."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for user, pwd in users_list:
            user_tuple = create_user(user, pwd)
            writer.writerow(user_tuple)


def read_users_db() -> list:
    """Зчитує дані з CSV-файлу."""
    users_db = []
    if not os.path.exists(CSV_FILE):
        raise FileNotFoundError(f"Файл {CSV_FILE} не знайдено.")

    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                users_db.append(row)
    return users_db


@log_event
def login(username: str, password: str) -> bool:
    """Автентифікація користувача."""
    if not username or not password:
        raise ValueError("Логін та пароль є обов'язковими.")

    target_hash = generate_hash(password, SALT)
    users_db = read_users_db()

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == target_hash:
            return True
    return False


def run_task3():
    """Головна функція Завдання 3."""
    print("=== Завдання 3: Хешування, CSV-база та JSON-логування ===")

    users_to_register = [
        ("forensic_lead", "SuperCryptoPass16!"),
        ("compliance_off", "CompliancePass2023#"),
        ("trainee_sec", "TraineeLongPassword16"),
        ("vendor_tech", "VendorSupportKey999"),
        ("archived_usr", "ArchivedAccount16!"),
        ("security_admin", "SecAdminAccess2023!"),
        ("analyst_01", "AnalystPassword16Var"),
        ("auditor_ext", "AuditorSecurePass1"),
        ("sys_operator", "OperatorPass16MinLen"),
        ("guest_user", "GuestAccountPass16!"),
    ]

    try:
        create_users(users_to_register)
        print("[+] Створено CSV-базу даних")

        users_db = read_users_db()
        print("\nЗчитана база даних:")
        for u, h in users_db:
            print(f"{u:<18} | {h}")

        print("\nПеревірка входу:")
        print(f"Успішний вхід: {login('forensic_lead', 'SuperCryptoPass16!')}")
        print(f"Невдалий вхід: {login('forensic_lead', 'WrongPassword16Chars')}")

    except (OSError, FileNotFoundError, PermissionError, ValidationError, ValueError) as e:
        print(f"[!] Помилка: {e}")


if __name__ == "__main__":
    run_task3()