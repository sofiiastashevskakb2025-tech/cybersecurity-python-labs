import sys
from datetime import datetime, timedelta, timezone

# Імпортуємо наші класи з task1
from labs.lab02.task1 import Admin, AuditLog, User, UserAccount


def run_demo():
    print("=== Демонстрація Завдання 1 ===")
    
    # Створюємо спільний журнал подій
    audit = AuditLog()
    
    # 1. Створення користувачів та встановлення паролів
    print("\n[1] Створення користувачів...")
    user1 = User(username="student", email="student@lpnu.ua", role="user")
    user1.set_password("SecurePass123!")
    account1 = UserAccount(user1, audit)
    print(user1)
    
    admin1 = Admin(username="root_admin", email="admin@corp.com")
    admin1.set_password("AdminPass!@#")
    account_admin = UserAccount(admin1, audit)
    print(admin1)
    
    # 2. Успішний і невдалий вхід
    print("\n[2] Спроби входу...")
    print("Вхід з неправильним паролем:", account1.login('student', 'wrongpass', '192.168.1.10'))
    print("Вхід з правильним паролем:", account1.login('student', 'SecurePass123!', '192.168.1.10'))
    
    # 3. Зміна email із валідацією
    print("\n[3] Зміна email із валідацією...")
    try:
        user1.email = "new_valid.email@lpnu.ua"
        print(f"Email успішно змінено на: {user1.email}")
        print("Спроба встановити неправильний email (invalid-email)...")
        user1.email = "invalid-email" # Це викличе помилку
    except ValueError as e:
        print(f"Очікувана помилка валідації: {e}")
        
    # 4. Права адміністратора
    print("\n[4] Робота з правами адміністратора...")
    admin1.grant_permission("VIEW_LOGS")
    admin1.grant_permission("DELETE_USERS")
    print(f"Після додавання прав: {admin1}")
    print(f"Чи має право DELETE_USERS? {admin1.has_permission('DELETE_USERS')}")
    
    admin1.revoke_permission("DELETE_USERS")
    print(f"Після видалення права DELETE_USERS: {admin1}")
    
    # 5. Завершення сеансу за таймаутом
    print("\n[5] Перевірка таймауту сесії...")
    print(f"Чи авторизований користувач зараз? {account1.is_authenticated()}")
    
    # Штучно відмотуємо час останньої активності на 20 хвилин назад (понад ліміт у 900 сек)
    account1.session.last_activity = datetime.now(timezone.utc) - timedelta(minutes=20)
    print(f"Чи авторизований після 20 хвилин неактивності? {account1.is_authenticated()}")
    
    # 6. Вихід із системи (logout)
    print("\n[6] Вихід із системи...")
    account_admin.login('root_admin', 'AdminPass!@#', '10.0.0.1')
    account_admin.logout()
    print(f"Чи авторизований адмін після виходу (logout)? {account_admin.is_authenticated()}")
    
    # 7. Записи AuditLog
    print("\n[7] Фінальний вивід AuditLog:")
    audit.show_all()


if __name__ == "__main__":
    # Перевіряємо аргументи командного рядка
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "demo":
            run_demo()
        elif command == "analyze":
            print("Команда analyze буде реалізована в task2.py для Варіанта 5")
        else:
            print(f"Невідома команда: {command}")
    else:
        print("Вкажіть команду: python -m labs.lab02.main demo")