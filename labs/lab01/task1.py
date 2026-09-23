import os
import random
import sys

# Налаштування шляхів
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


# === БЛОК 3 === (Логіка оцінки)
def check_password_strength(password, criteria, forbidden, all_passwords):
    min_length = criteria["min_length"]

    if password in forbidden or len(password) < min_length:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)

    security_checks = [has_digit, has_upper, has_lower, has_special]
    matched_criteria = sum(security_checks)

    if matched_criteria == 4:
        is_unique = all_passwords.count(password) == 1
        if len(password) >= min_length + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"
    elif matched_criteria >= 2:
        return "Середній"
    return "Слабкий"


# === БЛОК 1 та БЛОК 2 === (Дані та Random)
def main():
    print("=" * 60)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)

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
    criteria = {
        "min_length": 12,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }
    forbidden_passwords = {"123", "test123", "access", "password1", "guest123", "admin"}

    # Блок 2 (Генерація випадкових копій)
    working_passwords = passwords.copy()
    for _ in range(3):
        random_pwd = random.choice(passwords)
        working_passwords.append(random_pwd)

    # === БЛОК 4 === (Виведення таблиці)
    print(f"\n{'№':<3} | {'Пароль':<20} | {'Довжина':<7} | {'Статус безпеки':<15}")
    print("-" * 60)
    for i, pwd in enumerate(working_passwords, start=1):
        status = check_password_strength(
            pwd, criteria, forbidden_passwords, working_passwords
        )
        print(f"{i:<3} | {pwd:<20} | {len(pwd):<7} | {status:<15}")


if __name__ == "__main__":
    main()
