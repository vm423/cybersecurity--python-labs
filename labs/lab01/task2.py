# labs/lab01/task2.py
"""Модуль системи розмежування доступу (RBAC).

Реалізує багаторівневий механізм контролю доступу користувачів до ресурсів
на основі міток кліренсу (clearance), статусів активності та списків блокування.
"""

import os
import sys

# Налаштування системного шляху для коректного імпорту з папки shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Імпорт ідентифікаційних даних студента
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def check_access(username, resource_level, users_dict, blocked_set):
    """Перевіряє можливість доступу користувача до захищеного ресурсу.

    Алгоритм послідовно оцінює наявність облікового запису, присутність
    у списку заблокованих, прапорець активності та рівень допуску.

    Args:
        username (str): Логін користувача, який запитує доступ.
        resource_level (int): Числовий рівень безпеки ресурсу (1-4).
        users_dict (dict): Репозиторій (база даних) користувачів та їхніх атрибутів.
        blocked_set (set): Список ідентифікаторів заблокованих суб'єктів.

    Returns:
        str: Вердикт системи безпеки ("ALLOW" або "DENY" із зазначенням причини).
    """
    # 1. Перевірка наявності облікового запису в базі даних
    if username not in users_dict:
        return "DENY (User not found)"

    # 2. Перевірка перебування суб'єкта у списку блокування
    if username in blocked_set:
        return "DENY (User is blocked)"

    user_data = users_dict[username]

    # 3. Перевірка адміністративного статусу облікового запису
    if not user_data["active"]:
        return "DENY (Account inactive)"

    # 4. Порівняння рівня допуску користувача з рівнем безпеки ресурсу
    if user_data["clearance"] >= resource_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


def main():
    """Головна функція програми для моделювання сценаріїв контролю доступу."""
    # Виведення інформаційного блоку лабораторної роботи
    print("=" * 60)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)

    # Текстові назви рівнів безпеки інформаційної системи (індекс = рівень - 1)
    security_levels = ("Basic", "Standard", "Protected", "Maximum")

    # Перелік захищених ресурсів системи та їхні рівні критичності (Варіант №5)
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

    # Профілі користувачів із зазначенням ролей, допусків та департаментів
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

    # Чорний список облікових записів системи (компрометація або звільнення)
    blocked_users = {"archived_usr", "terminated_vendor", "security_reach"}

    # Виведення початкової конфігурації захищених об'єктів
    print("\n[СПИСОК РЕСУРСІВ СИСТЕМИ]:")
    for name, level in resources:
        text_level = security_levels[level - 1]
        print(f"Ресурс: {name:<25} | Рівень безпеки: {text_level}")

    print("\n" + "=" * 60)
    print("[РЕЗУЛЬТАТИ ПЕРЕВІРКИ СИСТЕМИ КОНТРОЛЮ ДОСТУПУ]:")
    print("=" * 60)

    # Формування тестового пулу суб'єктів (валідаційні та аномальні профілі)
    test_usernames = list(users.keys()) + ["terminated_vendor", "unknown_guest"]

    # Ітераційний запуск матриці доступу для кожного користувача до кожного ресурсу
    for username in test_usernames:
        print(f"\nПеревірка прав для користувача: {username}")
        print("-" * 50)
        for res_name, res_level in resources:
            verdict = check_access(username, res_level, users, blocked_users)
            print(f"user=[{username:<15}] resource=[{res_name:<20}] -> {verdict}")


if __name__ == "__main__":
    main()
