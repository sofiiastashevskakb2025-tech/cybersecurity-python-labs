import os
import sys

# Підключення модуля з персональними даними
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанту 5
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
        "active": False,
    },
}

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

security_levels = ("Basic", "Standard", "Protected", "Maximum")
blocked_users = {"archived_usr", "terminated_vendor", "security_breach"}


def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """Перевіряє доступ користувача за алгоритмом."""
    if username not in users:
        return False, "User not found"
    if username in blocked_users:
        return False, "User is blocked"
    if not users[username]["active"]:
        return False, "Account inactive"
    if users[username]["clearance"] >= resource_level:
        return True, ""
    return False, "Insufficient clearance"


def run_task2():
    """Виконує Завдання 2 та виводить результати."""
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=== Завдання 2: Багаторівнева система контролю доступу ===\n")

    # 1. Вивід усіх ресурсів із текстовою назвою рівня безпеки
    print("Список ресурсів системи:")
    for res_name, res_lvl in resources:
        level_text = security_levels[res_lvl - 1]
        print(f" - {res_name}: {level_text}")

    print("\nРезультати перевірки доступу:")

    # 2. Перевірка доступу користувачів до ресурсів
    test_users = list(users.keys()) + ["external_guest"]

    for username in test_users:
        for res_name, res_lvl in resources:
            allowed, reason = check_access(username, res_lvl)
            if allowed:
                res_str = "ALLOW"
            else:
                res_str = f"DENY ({reason})"
            print(f"user=[{username}] resource=[{res_name}] -> {res_str}")


if __name__ == "__main__":
    run_task2()