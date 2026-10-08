import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Задаємо константу кількості ітерацій для алгоритму PBKDF2
HASH_ITERATIONS = 100000

# Оголошуємо базовий клас для представлення користувача
class User:

    # Конструктор класу, який ініціалізує атрибути при створенні об'єкта
    def __init__(self, username: str, email: str, role: str, active: bool = True):

        # Зберігаємо передане ім'я користувача у властивість об'єкта
        self.username = username

        # Зберігаємо роль користувача у властивість об'єкта
        self.role = role

        # Зберігаємо статус активності акаунта у властивість об'єкта
        self.active = active

        # Ініціалізуємо приватний атрибут для хешу пароля (початкове значення None)
        self.__password_hash = None

        # Ініціалізуємо приватний атрибут для солі пароля (початкове значення None)
        self.__password_salt = None

        # Присвоюємо значення електронної пошти через setter-метод для валідації
        self.email = email

    # Декоратор property створює геттер для безпечного читання захищеного email
    @property
    def email(self) -> str:

        # Повертаємо внутрішнє значення захищеного атрибута _email
        return self._email

    # Декоратор setter дозволяє контролювати процес зміни або запису email
    @email.setter
    def email(self, value: str):

        # Визначаємо регулярний вираз для перевірки правильності написання пошти
        pattern = r"^[a-zA-Z][a-zA-Z0-9.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        # Перевіряємо, чи відповідає переданий рядок заданому патерну
        if not re.match(pattern, value):

            # Якщо не відповідає, викидаємо виняток помилки значення
            raise ValueError(f"Неправильний формат email: {value}")

        # Якщо перевірка успішна, зберігаємо значення у внутрішній атрибут
        self._email = value

    # Метод для генерації та збереження нового пароля користувача
    def set_password(self, password: str):

        # Генеруємо 16 випадкових байтів криптографічної солі
        self.__password_salt = os.urandom(16)

        # Створюємо хеш пароля за допомогою PBKDF2 з алгоритмом SHA-256
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", 
            password.encode('utf-8'), 
            self.__password_salt, 
            HASH_ITERATIONS
        )

    # Метод для перевірки правильності введеного користувачем пароля
    def check_password(self, password: str) -> bool:

        # Перевіряємо, чи існують сіль та хеш (чи встановлювався пароль взагалі)
        if not self.__password_salt or not self.__password_hash:

            # Якщо пароль не задано, повертаємо False
            return False

        # Обчислюємо тестовий хеш для введеного пароля з тією ж сіллю
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", 
            password.encode('utf-8'), 
            self.__password_salt, 
            HASH_ITERATIONS
        )

        # Порівнюємо справжній хеш із тестовим у захищений від timing-атак спосіб
        return hmac.compare_digest(self.__password_hash, test_hash)

    # Метод для деактивації облікового запису
    def deactivate(self):

        # Змінюємо статус активності на False
        self.active = False

    # Спеціальний метод для формування рядкового представлення об'єкта User
    def __str__(self):

        # Визначаємо текстовий еквівалент статусу активності
        status = "Active" if self.active else "Inactive"

        # Формуємо та повертаємо рядок із базовими даними користувача
        return f"User({self.username}, {self.email}, Role: {self.role}, {status})"


# Оголошуємо клас Admin, який успадковує всі властивості від класу User
class Admin(User):

    # Конструктор класу адміністратора з підтримкою опціонального списку прав
    def __init__(self, username: str, email: str, active: bool = True, permissions: list | None = None):

        # Викликаємо конструктор батьківського класу User через суперфункцію super()
        super().__init__(username, email, role="admin", active=active)

        # Перетворюємо переданий список дозволів у множину або створюємо порожню множину
        self.permissions = set(permissions) if permissions else set()

    # Метод для додавання нового права адміністратору
    def grant_permission(self, permission: str):

        # Додаємо дозвіл до множини прав
        self.permissions.add(permission)

    # Метод для видалення певного права у адміністратора
    def revoke_permission(self, permission: str):

        # Видаляємо дозвіл із множини без виникнення помилок при його відсутності
        self.permissions.discard(permission)

    # Метод для перевірки наявності конкретного дозволу у адміна
    def has_permission(self, permission: str) -> bool:

        # Повертаємо логічне значення наявності елемента у множині
        return permission in self.permissions

    # Перевизначаємо метод __str__ для додавання інформації про права адміністратора
    def __str__(self):

        # Отримуємо базовий рядок від батьківського методу __str__
        base_str = super().__str__()

        # Додаємо до нього перелік прав та повертаємо результат
        return f"{base_str} | Permissions: {self.permissions}"


# Задаємо константу таймауту сесії у секундах (900 секунд = 15 хвилин)
SESSION_TIMEOUT_SEC = 900

# Оголошуємо клас для управління сеансом користувача
class Session:

    # Конструктор класу сесії приймає IP-адресу клієнта
    def __init__(self, ip: str):

        # Зберігаємо IP-адресу у властивість об'єкта
        self.ip = ip

        # Фіксуємо точний час створення сесії у форматі UTC
        self.login_time = datetime.now(timezone.utc)

        # Встановлюємо час останньої активності рівним часу входу
        self.last_activity = self.login_time

    # Метод для оновлення часу останньої активності сеансу
    def touch(self):

        # Оновлюємо значення last_activity поточним часом в UTC
        self.last_activity = datetime.now(timezone.utc)

   # Метод для перевірки, чи сесія є активною відповідно до заданого таймауту
    def is_active(self, timeout_sec: int) -> bool:

        # Перевіряємо, чи є таймаут додатним числом
        if timeout_sec <= 0:

            # Якщо ні, одразу викликаємо виняток ValueError без зайвого try-except (виправляє помилку TRY203)
            raise ValueError("Таймаут повинен бути більше нуля")

        # Обчислюємо часову різницю між поточним моментом і останньою активністю
        diff = datetime.now(timezone.utc) - self.last_activity

        # Повертаємо True, якщо різниця не перевищує ліміт таймауту
        return diff <= timedelta(seconds=timeout_sec)


# Використовуємо декоратор dataclass для створення структури запису аудиту
@dataclass
class AuditRecord:
    timestamp: datetime  # Час фіксації події
    username: str        # Ім'я користувача, пов'язаного з подією
    action: str          # Назва виконаної дії


# Оголошуємо клас для ведення логів подій безпеки
class AuditLog:

    # Конструктор класу ініціалізує порожній список для збереження записів
    def __init__(self):

        # Створюємо порожній список для об'єктів AuditRecord
        self.records = []

    # Метод для додавання нового запису про подію в лог
    def add_log(self, username: str, action: str):

        # Створюємо новий екземпляр запису аудиту з поточним часом
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action
        )

        # Додаємо створений запис до загального списку логів
        self.records.append(record)

    # Метод для виведення всіх збережених записів аудиту в консоль
    def show_all(self):

        # Цикл для перебору кожного запису у списку рекордистів
        for record in self.records:

            # Виводимо відформатований рядок із часом, ім'ям і дією
            print(f"[{record.timestamp.isoformat()}] {record.username} - {record.action}")


# Оголошуємо клас UserAccount, що об'єднує User, Session та AuditLog через композицію
class UserAccount:

    # Конструктор приймає об'єкт користувача та опціональний об'єкт журналу аудиту
    def __init__(self, user: User, audit_log: AuditLog | None = None):

        # Зберігаємо об'єкт користувача у властивість акаунта
        self.user = user

        # Зберігаємо або створюємо новий екземпляр логу аудиту
        self.audit_log = audit_log if audit_log else AuditLog()

        # Початково активна сесія відсутня (дорівнює None)
        self.session = None

    # Метод для виконання процедури входу користувача в систему
    def login(self, username: str, password: str, ip: str) -> bool:

        # Перевіряємо відповідність імені та чи активний сам користувач
        if self.user.username != username or not self.user.active:

            # Записуємо подію невдалого входу в аудит
            self.audit_log.add_log(username, "login_failure")

            # Повертаємо False як ознаку невдачі
            return False

        # Перевіряємо правильність введеного пароля через метод користувача
        if self.user.check_password(password):

            # Створюємо новий об'єкт сеансу з переданою IP-адресою
            self.session = Session(ip)

            # Оновлюємо мітку часу активності сесії
            self.session.touch()

            # Записуємо подію успішного входу в журнал аудиту
            self.audit_log.add_log(username, "login_success")

            # Повертаємо True як ознаку успішної авторизації
            return True

        else:

            # Якщо пароль невірний, фіксуємо невдалу спробу в аудиті
            self.audit_log.add_log(username, "login_failure")

            # Повертаємо False
            return False

    # Метод перевірки, чи є користувач авторизованим на даний момент
    def is_authenticated(self) -> bool:

        # Перевіряємо, чи взагалі існує активна сесія
        if not self.session:

            # Якщо сесії немає, повертаємо False
            return False

        # Перевіряємо, чи не закінчився час сеансу за допомогою константи таймауту
        if self.session.is_active(SESSION_TIMEOUT_SEC):

            # Якщо сесія дійсна, подовжуємо її термін через touch()
            self.session.touch()

            # Повертаємо True
            return True

        else:

            # Якщо час минув, знищуємо сесію та повертаємо False
            self.session = None
            return False

    # Метод для виходу користувача із системи (завершення сеансу)
    def logout(self):

        # Перевіряємо наявність активної сесії перед виходом
        if self.session:

            # Записуємо подію виходу в журнал аудиту
            self.audit_log.add_log(self.user.username, "logout")

            # Очищаємо посилання на сесію
            self.session = None

    # Спеціальний магічний метод для доступу до внутрішніх компонентів через квадратні дужки
    def __getitem__(self, key):

        # Перевіряємо, чи запитують об'єкт користувача
        if key == "user":
            return self.user

        # Перевіряємо, чи запитують поточну сесію
        elif key == "session":
            return self.session

        # Перевіряємо, чи запитують журнал аудиту
        elif key == "audit_log":
            return self.audit_log

        else:
            # Викидаємо виняток для невідомих або заборонених ключів
            raise KeyError(f"Доступ до ключа '{key}' заборонено або ключ не існує")

    # Спеціальний магічний метод для зміни внутрішніх компонентів за ключем
    def __setitem__(self, key, value):

        # Перевіряємо, чи намагаються оновити користувача
        if key == "user":

            # Перевіряємо тип значення на відповідність класу User
            if not isinstance(value, User):
                raise TypeError("Значення має бути об'єктом класу User")

            # Зберігаємо нового користувача
            self.user = value

        # Перевіряємо, чи намагаються оновити сесію
        elif key == "session":

            # Перевіряємо тип значення на відповідність класу Session або None
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення має бути об'єктом класу Session або None")

            # Зберігаємо нову сесію
            self.session = value

        else:
            # Викидаємо виняток для зміни будь-яких інших ключів
            raise KeyError(f"Зміна ключа '{key}' заборонена")