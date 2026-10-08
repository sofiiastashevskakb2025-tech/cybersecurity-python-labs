# Імпортуємо модуль argparse для розбору командного рядка
import argparse

# Імпортуємо модуль csv для збереження табличних звітів
import csv

# Імпортуємо модуль json для взаємодії з файлами JSON-формату
import json

# Імпортуємо модуль logging для виведення інформаційних повідомлень та помилок
import logging

# Імпортуємо модуль re для виконання операцій з регулярними виразами
import re

# Імпортуємо модуль socket для роботи з мережевими сокетами і портами
import socket

# Імпортуємо модуль time для вимірювання часу виконання та пауз
import time

# Імпортуємо декоратор dataclass для створення структур даних
from dataclasses import dataclass

# Імпортуємо клас Path для зручної маніпуляції файловими шляхами
from pathlib import Path

# Імпортуємо типи List та Dict для забезпечення аннотацій типів

# Створюємо ізольований екземпляр логера спеціально для цього модуля
logger = logging.getLogger("task2_scanner")

# Оголошуємо клас даних для представлення результату сканування одного порту
@dataclass
class ScanResult:
    host: str            # Цільовий хост (IP або домен)
    port: int            # Порт, який перевірявся
    service: str         # Назва виявленого сервісу
    status: str          # Статус доступності (ONLINE, OFFLINE, ERROR)
    response_time: str   # Час відповіді у мілісекундах
    notes: str           # Додаткові примітки щодо результату перевірки

# Функція для ініціалізації параметрів глобального логування
def setup_logging(verbose: bool):

    # Визначаємо рівень деталізації логів на основі прапорця verbose
    level = logging.DEBUG if verbose else logging.INFO

    # Налаштовуємо базові параметри виводу повідомлень логера
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s"
    )

# Функція для валідації формату введеного хоста (IP або доменне ім'я)
def is_valid_host(host: str) -> bool:

    # Задаємо регулярний вираз для перевірки IPv4-адрес
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

    # Задаємо регулярний вираз для перевірки коректних доменних імен
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{2,63}$"
    
    # Повертаємо True, якщо хост є валідним IP, доменом або значенням localhost
    return bool(re.match(ip_pattern, host) or re.match(domain_pattern, host) or host == "localhost")

# Функція для завантаження списку цілей із зазначеного JSON-файлу
def load_targets(file_path: Path) -> list[dict]:

    # Перевіряємо фізичну наявність файлу за допомогою методу pathlib
    if not file_path.exists():

        # Логуємо помилку відсутності файлу
        logger.error(f"Файл не знайдено: {file_path}")

        # Повертаємо порожній список
        return []
        
    try:
        # Відкриваємо файл у режимі читання з кодуванням UTF-8
        with open(file_path, 'r', encoding='utf-8') as f:

            # Декодуємо вміст JSON у структуру даних Python і повертаємо її
            data = json.load(f)
            return data

    except (json.JSONDecodeError, OSError) as e:

        # Логуємо виняток у разі пошкодження JSON або системної помилки читання
        logger.error(f"Помилка читання файлу {file_path}: {e}")

        # Повертаємо порожній список при невдачі
        return []

# Функція для перевірки доступності мережевого порту на заданому хості
def check_port(host: str, port: int, timeout: int) -> ScanResult:

    # Встановлюємо назву сервісу за замовчуванням як невідому
    service = "UNKNOWN"

    # Створюємо словник стандартних відповідностей портів та їхніх сервісів
    common_services = {80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 53: "DNS"}

    # Якщо перевіряється стандартний порт, присвоюємо відповідну назву сервісу
    if port in common_services:
        service = common_services[port]

    # Створюємо об'єкт мережевого сокета для протоколу TCP через IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Встановлюємо таймаут очікування відповіді від сокета
    sock.settimeout(timeout)
    
    # Запам'ятовуємо час початку спроби з'єднання
    start_time = time.time()

    try:
        # Виконуємо спробу підключення за допомогою connect_ex (повертає код результату)
        result = sock.connect_ex((host, port))

        # Фіксуємо час завершення спроби з'єднання
        end_time = time.time()

        # Обчислюємо час кругового обходу (RTT) у мілісекундах та округлюємо
        resp_time_ms = round((end_time - start_time) * 1000, 1)
        
        # Перевіряємо, чи успішним було з'єднання (код дорівнює 0)
        if result == 0:
            return ScanResult(host, port, service, "ONLINE", f"{resp_time_ms} ms", "OK")
        else:
            return ScanResult(host, port, service, "OFFLINE", "TIMEOUT", "Connection refused")
            
    except TimeoutError:
        return ScanResult(host, port, service, "OFFLINE", "TIMEOUT", "Connection timed out")

    except socket.gaierror:
        return ScanResult(host, port, service, "ERROR", "-", "DNS resolution failed")

    except OSError as e:
        return ScanResult(host, port, service, "ERROR", "-", str(e))

    finally:
        # Гарантовано закриваємо сокет у блоці finally незалежно від результатів
        sock.close()

# Функція для експорту підсумків сканування у CSV-файл
def save_to_csv(results: list[ScanResult], out_file: Path):

    try:
        # Відкриваємо файл для запису утилітарних даних з кодуванням UTF-8
        with open(out_file, 'w', newline='', encoding='utf-8') as f:

            # Створюємо об'єкт writer для запису CSV рядків
            writer = csv.writer(f)

            # Записуємо рядок заголовків таблиці
            writer.writerow(["Target Host", "Port", "Service", "Status", "Response Time", "Notes"])

            # Проходимося циклом по кожному результату сканування
            for r in results:

                # Записуємо параметри об'єкта як рядок таблиці
                writer.writerow([r.host, r.port, r.service, r.status, r.response_time, r.notes])

        # Логуємо інформацію про успішне збереження звіту
        logger.info(f"Detailed scan report saved to {out_file}")

    except OSError as e:
        logger.error(f"Помилка запису в CSV: {e}")

# Головна управляюча функція процесу сканування
def run_scanner(args):

    # Ініціалізуємо налаштування логування відповідно до аргументів
    setup_logging(args.verbose)

    # Перетворюємо вхідний шлях рядка у кросплатформний об'єкт Path
    targets_path = Path(args.targets)
    
    # Виводимо інформаційне повідомлення про старт сканування
    logger.info(f"Starting service availability scan from target list {targets_path}...")
    
    # Зчитуємо список цілей з файлу
    targets = load_targets(targets_path)

    # Перевіряємо, чи існують цілі для перевірки
    if not targets:
        return

    # Ініціалізуємо порожній список результатів та лічильники статистики
    results = []
    online_count = 0
    offline_count = 0

    # Друкуємо заголовок таблиці результатів у консоль зі спеціальним форматуванням
    print(f"\n{'Target Host':<16} {'Port':<6} {'Service':<8} {'Status':<8} {'Response Time':<14} {'Notes'}")
    print("-" * 70)

    # Перебираємо кожну ціль із завантаженого зі списку масиву
    for target in targets:

        # Отримуємо значення хоста та порту за допомогою методів словника
        host = target.get("host", "")
        port = target.get("port", 0)
        
        # Здійснюємо перевірку валідності хоста регулярними виразами
        if not is_valid_host(host):
            logger.warning(f"Invalid host format skipped: {host}")
            continue
            
        # Запускаємо перевірку доступності порту
        scan_res = check_port(host, int(port), args.timeout)

        # Додаємо отриманий результат до загального масиву
        results.append(scan_res)
        
        # Виводимо рядок результату перевірки поточної цілі на екран
        print(f"{scan_res.host:<16} {scan_res.port:<6} {scan_res.service:<8} {scan_res.status:<8} {scan_res.response_time:<14} {scan_res.notes}")
        
        # Інкрементуємо відповідний лічильник статистики залежно від статусу
        if scan_res.status == "ONLINE":
            online_count += 1
        else:
            offline_count += 1

    # Обчислюємо загальну кількість перевірених вузлів
    total = online_count + offline_count
    
    # Виводимо блок підсумкової статистики на екран
    print("\n=== Scan Statistics ===")
    print(f"Total Scanned : {total}")

    if total > 0:
        print(f"Online        : {online_count} ({(online_count/total)*100:.1f}%)")
        print(f"Offline       : {offline_count} ({(offline_count/total)*100:.1f}%)")
    
    # Перевіряємо, чи вказано аргумент збереження результатів у CSV
    if args.out_csv:
        save_to_csv(results, Path(args.out_csv))

# Блок перевірки виконання скрипта напряму як головної програми
if __name__ == "__main__":

    # Ініціалізуємо парсер аргументів командного рядка з описом програми
    parser = argparse.ArgumentParser(description="Network Service Availability Scanner")

    # Додаємо обов'язковий аргумент шляху до цілей --targets
    parser.add_argument("--targets", required=True, help="Шлях до JSON файлу з цілями")

    # Додаємо числовий аргумент таймауту з'єднання за замовчуванням 2 секунди
    parser.add_argument("--timeout", type=int, default=2, help="Таймаут з'єднання у секундах")

    # Додаємо необов'язковий аргумент для збереження результатів у CSV
    parser.add_argument("--out-csv", help="Шлях для збереження результатів у CSV")

    # Додаємо булевий прапорець для активації детального логування
    parser.add_argument("--verbose", action="store_true", help="Детальне логування")
    
    # Здійснюємо парсинг переданих аргументів командного рядка
    args = parser.parse_args()

    # Передаємо розібрані параметри у головну функцію сканера
    run_scanner(args)