import os
import random
import sys

# Додаємо шлях до суміжної папки 'shared' у системний шлях
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

try:
    from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER
except ImportError:
    # Заглушки на випадок, якщо файл запускається без папки shared
    GROUP_NAME = "Група-1"
    STUDENT_NAME = "Студент"
    VARIANT_NUMBER = 1

# ВХІДНІ ДАНІ ТА КРИТЕРІЇ ОЦІНЮВАННЯ

# Початковий список паролів для аналізу
PASSWORDS = [
    "DataS3cur3!",
    "123",
    "Crypt0@Analysis",
    "test123",
    "Quantum#2023",
    "access",
    "Secur1ty@Pro",
    "password1",
    "Adv@nced123",
    "jrwngoiwrjgwe",
    "qqqq"
]

# Словник із критеріями надійності пароля
CRITERIA = {
    "min_length": 12,        # Мінімальна довжина пароля
    "require_digits": True,  # Вимога наявності цифр
    "require_upper": True,   # Вимога наявності великих літер
    "require_special": True, # Вимога наявності спецсимволів
}

# Множина (set) заборонених / ненадійних паролів
FORBIDDEN_PASSWORDS = {
    "123",
    "test123",
    "access",
    "password1",
    "guest123",
    "admin",
}

# ФУНКЦІЯ ОЦІНЮВАННЯ НАДІЙНОСТІ ПАРОЛЯ

def evaluate_password(
    password: str, passwords_list: list, criteria: dict, forbidden: set
) -> str:
    """Аналізує пароль за критеріями та повертає текстову категорію надійності."""
    
    # 1. Перевірка на порожній пароль
    if not password:
        return "Порожній пароль"
        
    min_len = criteria.get("min_length", 12)

    # 2. Якщо пароль є у списку заборонених АБО його довжина менша за мінімальну
    if password in forbidden or len(password) < min_len:
        return "Заборонений"

    # Перевіряємо наявність типів символів у паролі
    has_digit = any(c.isdigit() for c in password)      # Чи є цифри
    has_upper = any(c.isupper() for c in password)      # Чи є великі літери
    has_lower = any(c.islower() for c in password)      # Чи є маленькі літери
    has_special = any(not c.isalnum() for c in password) # Чи є спецсимволи

    # Чи відповідає пароль усім 4 вимогам
    meets_all = has_digit and has_upper and has_lower and has_special
    
    # Чи є пароль унікальним у списку
    is_unique = passwords_list.count(password) == 1

    # 3. Категорія "Дуже сильний" (усі типи символів + довжина >= 16 + унікальний)
    if meets_all and len(password) >= min_len + 4 and is_unique:
        return "Дуже сильний"

    # 4. Категорія "Сильний" (усі типи символів, але довжина < 16)
    if meets_all and len(password) < min_len + 4:
        return "Сильний"

    # 5. Категорія "Середній" (відповідає вимогам або містить хоча б один тип символів)
    if meets_all or (has_digit or has_upper or has_special or has_lower):
        return "Середній"

    # 6. Категорія "Слабкий"
    return "Слабкий"

# 4. ГОЛОВНА ФУНКЦІЯ ВИКОНАННЯ

def run_task1():
    """Виводить шапку з даними з shared.student та формує таблицю виводу."""
    
    # 1. Виводимо ПІБ, групу та номер варіанта, імпортовані з shared.student
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 51)
    print()  # Порожній рядок для відступу

    # Задаємо зерно для генератора випадкових чисел (для однакового відтворення)
    random.seed(42)
    
    # Обираємо 3 випадкові індекси зі списку PASSWORDS та створюємо дублікати
    sampled_indices = random.sample(range(len(PASSWORDS)), 3)
    extended_passwords = PASSWORDS.copy()
    for idx in sampled_indices:
        extended_passwords.append(PASSWORDS[idx])

    # 2. Вивід підсумкової таблиці
    print(f"{'Пароль':<20} | {'Оцінка надійності'}")
    print("-" * 42)

    # Циклом проходимо по всіх паролях та виводимо оцінку
    for pwd in extended_passwords:
        category = evaluate_password(
            pwd, extended_passwords, CRITERIA, FORBIDDEN_PASSWORDS
        )
        display_pwd = "<EMPTY>" if not pwd else pwd
        print(f"{display_pwd:<20} | {category}")

# 5. ТОЧКА ВХОДУ В ПРОГРАМУ

if __name__ == "__main__":
    run_task1()