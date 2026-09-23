import os
import sys

# Додаємо шлях до кореня проєкту
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


# === БЛОК 2: АЛГОРИТМ ПЕРЕВІРКИ ===
def check_access(username, resource_level, users_dict, blocked_set):
    """Реалізує алгоритм багаторівневої перевірки доступу."""
    if username not in users_dict:
        return "DENY (User not found)"

    if username in blocked_set:
        return "DENY (User is blocked)"

    user_data = users_dict[username]

    if user_data["active"] is False:
        return "DENY (Account inactive)"

    if user_data["clearance"] >= resource_level:
        return "ALLOW"
    else:
        return "DENY (Insufficient clearance)"


# === БЛОК 1 та БЛОК 3: ДАНІ ТА ЦИКЛИ ТЕСТУВАННЯ ===
def main():
    print("=" * 60)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)

    security_levels = ("Basic", "Standard", "Protected", "Maximum")

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

    blocked_users = {"archived_usr", "terminated_vendor", "security_reach"}

    # Крок 2: Список ресурсів
    print("\n[СПИСОК РЕСУРСІВ СИСТЕМИ]:")
    for name, level in resources:
        text_level = security_levels[level - 1]
        print(f"Ресурс: {name:<25} | Рівень безпеки: {text_level}")

    # Крок 3 та 4: Тестування та звіт
    print("\n" + "=" * 60)
    print("[РЕЗУЛЬТАТИ ПЕРЕВІРКИ СИСТЕМИ КОНТРОЛЮ ДОСТУПУ]:")
    print("=" * 60)

    test_usernames = list(users.keys()) + ["terminated_vendor", "unknown_guest"]

    for username in test_usernames:
        print(f"\nПеревірка прав для користувача: {username}")
        print("-" * 50)
        for res_name, res_level in resources:
            verdict = check_access(username, res_level, users, blocked_users)
            print(f"user=[{username:<15}] resource=[{res_name:<20}] -> {verdict}")


if __name__ == "__main__":
    main()
