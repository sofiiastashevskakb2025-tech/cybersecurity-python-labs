import os
import random
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
STUDENT_NAME = "Сташевська Софія Богданівна"
GROUP_NAME = "КБ-202"
VARIANT_NUMBER = 5

passwords = [
    "DataS3cur3!",
    "123",
    "Crypto@Analysis",
    "test123",
    "Quantum#2023",
    "access",
    "Security@Pro",
    "password1",
    "Adv@nced123",
    "guest123",
]

# Критерії оцінювання надійності
criteria = {
    "min_length": 12,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "123",
    "test123",
    "access",
    "password1",
    "guest123",
    "admin",
}


def evaluate_password(pwd: str, all_passwords: list) -> str:
    #рівень надійності пароля згідно з критеріями
    min_len = criteria["min_length"]

    if pwd in forbidden_passwords or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_spec = any(not c.isalnum() for c in pwd)

    meets_all_criteria = has_digit and has_upper and has_spec

    if meets_all_criteria:
        is_unique = all_passwords.count(pwd) == 1
        if len(pwd) >= (min_len + 4) and is_unique:
            return "Дуже сильний"
        return "Сильний"
    
    if has_digit or has_upper or has_spec:
        return "Середній"

    return "Слабкий"


def run_task1():
 
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=== Завдання 1: Аналізатор надійності паролів ===")

# повторне використання паролів
    working_passwords = passwords.copy()
    random_indices = random.choices(range(len(passwords)), k=3)
    for idx in random_indices:
        working_passwords.append(passwords[idx])

#таблиця
    print(f"\n{'№':<4} | {'Пароль':<20} | {'Категорія'}")
    print("-" * 45)

    for idx, pwd in enumerate(working_passwords, start=1):
        category = evaluate_password(pwd, working_passwords)
        print(f"{idx:<4} | {pwd:<20} | {category}")


if __name__ == "__main__":
    run_task1()