import os
import sys

# 1. СИСТЕМНІ НАЛАШТУВАННЯ ТА ІМПОРТИ

# Додаємо шлях до суміжної папки 'shared' у системний шлях
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

# Імпортуємо особисті дані з модуля shared.student
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# 2. ВХІДНІ ДАНІ СИСТЕМИ (КОРИСТУВАЧІ, РЕСУРСИ, РІВНІ БЕЗПЕКИ)

# Словник користувачів системи з їхніми атрибутами:
# role - роль, clearance - рівень доступу (1-4), department - відділ, active - статус акаунта
users = {
    "forensic_lead": {
        "role": "forensic_analyst",
        "clearance": 4,
        "department": "Forensics",
        "active": True,
    },
    "compliance_off": {
        "role": "compliance_officer",
        "clearance": 3,
        "department": "Compliance",
        "active": True,
    },
    "trainee_sec": {
        "role": "trainee",
        "clearance": 1,
        "department": "Training",
        "active": True,
    },
    "vendor_tech": {
        "role": "vendor_support",
        "clearance": 2,
        "department": "Vendor",
        "active": True,
    },
    "archived_usr": {
        "role": "archived",
        "clearance": 1,
        "department": "Archive",
        "active": False,  # Акаунт неактивний
    },
}

# Список ресурсів системи у вигляді кортежів: (назва_ресурсу, необхідний_рівень_доступу)
resources = [
    ("forensic_images", 4),
    ("compliance_reports", 3),
    ("training_videos", 1),
    ("vendor_tools", 2),
    ("evidence_locker", 4),
    ("certification_docs", 1),
    ("audit_findings", 3),
    ("chain_of_custody", 4),
    ("support_tickets", 2),
    ("learning_modules", 1),
]

# Кортеж із текстовими назвами рівнів безпеки (індекси 0..3 відповідають рівням 1..4)
security_levels = ("Basic", "Standard", "Protected", "Maximum")

# Множина (set) заблокованих користувачів для швидкого пошуку
blocked_users = {"archived_usr", "terminated_vendor", "security_breach"}

# 3. ФУНКЦІЯ ПЕРЕВІРКИ ДОСТУПУ (CHECK_ACCESS)

def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """
    Перевіряє, чи має користувач доступ до ресурсу.
    Повертає кортеж: (True/False, "причина відмови якщо False").
    """
    # 1. Перевірка: чи існує користувач у базі
    if username not in users:
        return False, "User not found"
    
    # 2. Перевірка: чи не заблокований користувач
    if username in blocked_users:
        return False, "User is blocked"
    
    # 3. Перевірка: чи активний акаунт користувача
    if not users[username]["active"]:
        return False, "Account inactive"
    
    # 4. Перевірка: чи достатній рівень доступу (clearance) у користувача
    if users[username]["clearance"] >= resource_level:
        return True, ""  # Доступ дозволено, причина порожня
    
    # Якщо рівень доступу занизький
    return False, "Insufficient clearance"

# 4. ГОЛОВНА ФУНКЦІЯ ВИКОНАННЯ ЗАВДАННЯ

def run_task2():
    """Виконує Завдання 2 та виводить результати у консоль."""
    
    # Вивід шапки з даними студента
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=== Завдання 2: Багаторівнева система контролю доступу ===\n")

    # 1. Вивід списку ресурсів із відповідним текстовим рівнем безпеки
    print("Список ресурсів системи:")
    for res_name, res_lvl in resources:
        # Отримуємо назву рівня з масиву security_levels (res_lvl - 1, бо індексація з 0)
        level_text = security_levels[res_lvl - 1]
        print(f" - {res_name}: {level_text}")

    print("\nРезультати перевірки доступу:")

    # 2. Формуємо список користувачів для перевірки (+ додаємо незареєстрованого гостя)
    test_users = list(users.keys()) + ["external_guest"]

    # Проходимо по кожному користувачу та кожному ресурсу
    for username in test_users:
        for res_name, res_lvl in resources:
            # Викликаємо функцію перевірки доступу
            allowed, reason = check_access(username, res_lvl)
            
            # Форматуємо результат у рядок (ALLOW або DENY з причиною)
            if allowed:
                res_str = "ДОЗВОЛЕНО"
            else:
                res_str = f"ВІДХИЛЕНО ({reason})"
            
            # Виводимо результат перевірки в консоль
            print(f"user=[{username}] resource=[{res_name}] -> {res_str}")


# 5. ТОЧКА ВХОДУ В ПРОГРАМУ

if __name__ == "__main__":
    run_task2()