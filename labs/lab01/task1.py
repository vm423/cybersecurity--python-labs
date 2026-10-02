# labs/lab01/task1.py
"""Модуль для комплексного аналізу надійності паролів.

Забезпечує перевірку паролів на відповідність безпековим критеріям,
враховує унікальність, довжину та наявність обов'язкових символів.
"""

import os
import random
import sys

# Додавання кореневої директорії проєкту до шляхів пошуку модулів Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Імпорт індивідуальних даних студента з загального пакета
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def check_password_strength(password, criteria, forbidden, all_passwords):
    """Визначає рівень безпеки пароля на основі заданих критеріїв.

    Args:
        password (str): Пароль для аналізу.
        criteria (dict): Словник із критеріями мінімальної довжини.
        forbidden (set): Набір скомпрометованих/заборонених паролів.
        all_passwords (list): Повний список паролів для оцінки унікальності.

    Returns:
        str: Текстовий статус надійності пароля.
    """
    min_length = criteria["min_length"]

    # Перевірка на присутність у чорному списку або недостатню довжину
    if password in forbidden or len(password) < min_length:
        return "Заборонений"

    # Перевірка наявності різних типів символів у структурі пароля
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    # Обчислення загальної кількості виконаних умов безпеки
    security_checks = [has_digit, has_upper, has_lower, has_special]
    matched_criteria = sum(security_checks)

    # Класифікація рівня складності пароля
    if matched_criteria == 4:
        # Пароль вважається унікальним, якщо він зустрічається у списку лише 1 раз
        is_unique = all_passwords.count(password) == 1
        if len(password) >= min_length + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"
    elif matched_criteria >= 2:
        return "Середній"
    return "Слабкий"


def main():
    """Головна функція програми для запуску демонстрації аналізу паролів."""
    # Виведення інформаційного заголовка з даними студента
    print("=" * 60)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)

    # Початковий масив тестових паролів для Варіанту №5
    passwords = [
        "DataS3cur3!",
        "123",
        "Crypt0@Analysis",
        "test123",
        "Quantum#2023",
        "access",
        "Secur1ty@Pro",
        "password1",
        "Adv@nced123",
        "guest123",
    ]

    # Словник вимог безпеки інформаційної системи
    criteria = {
        "min_length": 12,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }

    # База заборонених та дефолтних паролів
    forbidden_passwords = {"123", "test123", "access", "password1", "guest123", "admin"}

    # Створення робочої копії списку для моделювання повторного використання
    working_passwords = passwords.copy()

    # Симуляція повторного використання: додаємо 3 випадкові паролі з наявних
    for _ in range(3):
        random_pwd = random.choice(passwords)
        working_passwords.append(random_pwd)

    # Виведення результатів аналізу у вигляді структурованої таблиці
    print(f"\n{'№':<3} | {'Пароль':<20} | {'Довжина':<7} | {'Статус безпеки':<15}")
    print("-" * 60)

    for i, pwd in enumerate(working_passwords, start=1):
        status = check_password_strength(
            pwd, criteria, forbidden_passwords, working_passwords
        )
        print(f"{i:<3} | {pwd:<20} | {len(pwd):<7} | {status:<15}")


if __name__ == "__main__":
    main()
