import os
import sys

# Підключення модуля з персональними даними
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from task1 import run_task1
from task2 import run_task2
from task3 import run_task3

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print("=" * 60)
    print(f"ЛАБОРАТОРНА РОБОТА №1 | ВАРІАНТ {VARIANT_NUMBER}")
    print(f"Виконав: {STUDENT_NAME} ({GROUP_NAME})")
    print("=" * 60)
    print("\n")

    # Запуск Завдання 1
    run_task1()
    print("\n" + "=" * 60 + "\n")

    # Запуск Завдання 2
    run_task2()
    print("\n" + "=" * 60 + "\n")

    # Запуск Завдання 3
    run_task3()
    print("\n" + "=" * 60 + "\n")
    print("Всі завдання успішно виконані!")


if __name__ == "__main__":
    main()