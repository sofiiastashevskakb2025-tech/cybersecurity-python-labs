import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

# 1. СИСТЕМНІ НАЛАШТУВАННЯ ТА ІМПОРТИ

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

try:
    from shared.student import VARIANT_NUMBER
except ImportError:
    VARIANT_NUMBER = 1  

# 2. КЛАСИ ПОМИЛОК, КОНСТАНТИ ТА ШЛЯХИ ДО ФАЙЛІВ

class ValidationError(Exception):
    """Власний клас винятку для фіксації помилок валідації пароля або логіна."""


SALT = str(VARIANT_NUMBER).zfill(5)
MIN_PASSWORD_LENGTH = 16

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

# 3. ФУНКЦІЇ ДЛЯ ХЕШУВАННЯ ТА ЛОГУВАННЯ В JSON

def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує криптографічний sha3_256 хеш пароля з додаванням солі."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий (мінімум {MIN_PASSWORD_LENGTH} символів)."
        )

    salted_data = (password + salt).encode("utf-8")
    return hashlib.sha3_256(salted_data).hexdigest()


def append_to_json_log(log_entry: dict):
    """Допоміжна функція для безпечного дописування подій у файл log.json."""
    os.makedirs(DATA_DIR, exist_ok=True)
    logs = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except (OSError, json.JSONDecodeError):
            logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)


def log_event(func):
    """Декоратор для логування спроб входу (автентифікації) у файл log.json."""
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
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            }
            append_to_json_log(log_entry)

        return result

    return wrapper

# 4. РОБОТА З КОРИСТУВАЧАМИ ТА БАЗОЮ ДАНИХ (CSV)

def create_user(username: str, password: str) -> tuple:
    """Валідує логін та пароль, замінюючи помилкові дані на спеціальні теги."""
    is_empty_user = not username or not username.strip()
    is_empty_pwd = not password or not password.strip()

    final_username = "<EMPTY_USERNAME>" if is_empty_user else username

    if is_empty_pwd:
        hash_val = "<EMPTY_PASSWORD>"
    elif is_empty_user:
        hash_val = "<NO_LOGIN>" # Нема логіну там де хеш паролю
    else:
        try:
            hash_val = generate_hash(password, SALT)
        except (ValueError, ValidationError):
            hash_val = "<INVALID_PASSWORD>"

    return (final_username, hash_val)


def create_users(users_list: list) -> list:
    """
    Приймає список користувачів. Зберігає У CSV ТІЛЬКИ валідних користувачів, 
    але повертає повний список (з тегами помилок) для відображення в терміналі.
    """
    os.makedirs(DATA_DIR, exist_ok=True)

    seen_usernames = set()
    processed_users = []
    valid_users_for_csv = []

    print("--- Процес реєстрації ---")
    for user, pwd in users_list:
        # 1. Якщо юзер або пароль порожні - виводимо повідомлення!
        if not user or not str(user).strip() or not pwd or not str(pwd).strip():
            print(f"[!] логін або пароль пустий (спроба: '{user}')")
            
        if user and user.strip():
            if user in seen_usernames:
                print(f"[!] Виявлено дублікат логіна: '{user}'")
                continue
            seen_usernames.add(user)

        user_tuple = create_user(user, pwd)
        processed_users.append(user_tuple)

        # 2. Зберігаємо у CSV тільки якщо немає тегів помилок (починаються з '<')
        if not user_tuple[0].startswith("<") and not user_tuple[1].startswith("<"):
            valid_users_for_csv.append(user_tuple)

        log_entry = {
            "event": "user_registration",
            "user": user_tuple[0],
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }
        append_to_json_log(log_entry)

    # 3. Записуємо у CSV тільки валідні дані
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for user_tuple in valid_users_for_csv:
            writer.writerow(user_tuple)
            
    return processed_users


def read_users_db() -> list:
    """Зчитує та повертає всі записи з CSV-бази даних користувачів."""
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
    """Перевіряє автентифікацію користувача порівнянням хешів."""
    if not username or len(username.strip()) == 0 or not password:
        raise ValueError("Логін та пароль є обов'язковими.")

    target_hash = generate_hash(password, SALT)
    users_db = read_users_db()

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == target_hash:
            return True
    return False

# 5. ГОЛОВНА ФУНКЦІЯ ВИКОНАННЯ (RUN_TASK3)

def run_task3():
    """Виконує Завдання 3: реєстрація користувачів, вивід бази та тестування входу."""

    users_to_register = [
        ("forensic_lead", "SuperCryptoPass16!"),
        ("compliance_off", "CompliancePass2023#"),
        ("trainee_sec", "TraineeLongPassword16"),
        ("vendor_tech", "UHiuvhfudhUUIIUD1372@"),
        ("archived_usr", "ArchivedAccount16!"),
        ("security_admin", "SecAdminAccess2023!"),
        ("analyst_01", "AnalystPassword16Var"),
        ("auditor_ext", "AuditorSecurePass1"),
        ("sys_operator", "OperatorPass16MinLen"),
        ("guest_user", "SWHIOWJhb")
    ]

    try:
        # 1. Реєструємо користувачів
        all_attempts = create_users(users_to_register)

        # 2. Виводимо ВСІ спроби реєстрації у термінал
        print("\n--- Усі спроби реєстрації (Для перевірки в терміналі) ---")
        print(f"{'Username':<16} | {'Hash / Status'}")
        print("-" * 74)

        for u, h in all_attempts:
            display_hash = h if h.startswith("<") else h[:32]
            print(f"{u:<16} | {display_hash}")
        print("\n")

        # 3. Перевірка автентифікації
        print("[3] Перевірка автентифікації:")

        test_cases = [
            (
                users_to_register[0][0],
                users_to_register[0][1],
                "вірний пароль",
            ),
            (
                users_to_register[1][0],
                "WrongPassword16Chars!",
                "невірний пароль",
            ),
        ] + [(u, p, "вірний пароль") for u, p in users_to_register[2:10]] 

        for username, password, pass_label in test_cases:
            is_success = login(username, password)
            status = "СХВАЛЕНО" if is_success else "ВІДХИЛЕНО"
            print(f"Спроба входу [{username} / {pass_label}]: {status}")

    except (
        OSError,
        FileNotFoundError,
        PermissionError,
        ValidationError,
        ValueError,
    ) as e:
        print(f"[!] Помилка: {e}")

# 6. ТОЧКА ВХОДУ В ПРОГРАМУ

if __name__ == "__main__":
    run_task3()