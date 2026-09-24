import csv
import datetime
import hashlib
import json
import os
import sys

# Підключаємо корінь проєкту для імпорту даних студента
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class ValidationError(Exception):
    """Виняток, який генерується, якщо пароль занадто короткий."""


# Створення персональної солі (для варіанту 5 це буде рядок "00005")
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує безпечний незворотний хеш на основі пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми!")

    # Для Варіанту 5 мінімальна довжина пароля становить 16 символів
    if len(password) < 16:
        raise ValidationError(
            f"Пароль занадто короткий ({len(password)} симв.). Мінімальна довжина: 16."
        )

    # Конкатенація пароля та солі
    data_to_hash = password + salt

    # Хешування за алгоритмом sha3_256
    hash_object = hashlib.sha3_256(data_to_hash.encode())
    return hash_object.hexdigest()


# Кортеж із 10 користувачів для реєстрації (усі паролі мають довжину 16+ символів)
users_to_register = (
    ("mar_vasylyshyn", "SuperSecurePassword2026!"),
    ("admin_cyber", "RootAccessRequired999#"),
    ("analyst_bob", "BobNeedsMoreThanSixteenChars"),
    ("trainee_sec", "TrainingHardEveryDay123!"),
    ("vendor_tech", "VendorSupportToken8888"),
    ("user_test1", "PasswordLengthIsSixteen!"),
    ("user_test2", "AnotherLongPasswordForLab"),
    ("user_test3", "CryptographyIsFun2026"),
    ("user_test4", "SafeHashingWithSha3_256"),
    ("user_test5", "ThisIsTheTenthUserPassword"),
)


def create_user(username: str, password: str) -> tuple:
    """Хешує пароль із персональною сіллю та повертає пару (логін, хеш)."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return (username, hash_value)


def create_users_csv(users_list):
    """Створює папку data та записує базу користувачів у users.csv."""
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
    os.makedirs(data_dir, exist_ok=True)

    file_path = os.path.join(data_dir, "users.csv")

    with open(file_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for username, password in users_list:
            user_entry = create_user(username, password)
            writer.writerow(user_entry)


def read_users_csv() -> list:
    """Зчитує вміст файлу users.csv у список для подальшої перевірки."""
    file_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "data/users.csv")
    )

    users_db = []
    with open(file_path, mode="r", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if row:
                users_db.append(row)
    return users_db


def log_event(func):
    """Декоратор, який автоматично записує спроби входу у файл log.json."""

    def wrapper(username: str, password: str, users_db: list) -> bool:
        result_bool = func(username, password, users_db)
        result_text = "success" if result_bool else "failure"

        log_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "data/log.json")
        )

        log_entry = {
            "event": "login",
            "user": username,
            "result": result_text,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": [],
            "kwargs": {},
        }

        logs_list = []
        if os.path.exists(log_path):
            try:
                with open(log_path, mode="r", encoding="utf-8") as log_file:
                    logs_list = json.load(log_file)
                    if not isinstance(logs_list, list):
                        logs_list = []
            except (OSError, json.JSONDecodeError):
                logs_list = []

        logs_list.append(log_entry)

        with open(log_path, mode="w", encoding="utf-8") as log_file:
            json.dump(logs_list, log_file, indent=4, ensure_ascii=False)

        return result_bool

    return wrapper


@log_event
def login(username: str, password: str, users_db: list) -> bool:
    """Здійснює автентифікацію користувача шляхом порівняння хешів."""
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми!")

    try:
        input_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False

    for db_username, db_hash in users_db:
        if db_username == username:
            return db_hash == input_hash

    return False


def main():
    print("=" * 60)
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("=" * 60)

    try:
        print("\n[КРОК 1]: Реєстрація користувачів та створення бази даних CSV...")
        create_users_csv(users_to_register)
        print("База даних користувачів (users.csv) успішно створена.")

        print("\n[КРОК 2]: Читання бази даних з файлу та виведення таблиці...")
        users_db = read_users_csv()

        print(
            f"{'№':<3} | {'Логін користувача':<25} | "
            f"{'Хеш-значення пароля (SHA3_256)':<64}"
        )
        print("-" * 100)
        for i, (username, pwd_hash) in enumerate(users_db, start=1):
            print(f"{i:<3} | {username:<25} | {pwd_hash}")

        print("\n[КРОК 3]: Тестування системи автентифікації користувачів...")
        print("-" * 60)

        # Тест 1: Успішний вхід
        print("Тест 1 (Правильні дані):")
        res1 = login("mar_vasylyshyn", "SuperSecurePassword2026!", users_db)
        print(f"Вхід для 'mar_vasylyshyn' -> {'УСПІШНО' if res1 else 'ВІДМОВЛЕНО'}")

        # Тест 2: Невдалий вхід (неправильний пароль)
        print("\nТест 2 (Неправильний пароль):")
        res2 = login("admin_cyber", "WrongPasswordButLongEnough123", users_db)
        print(f"Вхід для 'admin_cyber' -> {'УСПІШНО' if res2 else 'ВІДМОВЛЕНО'}")

        # Тест 3: Невдалий вхід (невідомий користувач)
        print("\nТест 3 (Невідомий користувач):")
        res3 = login("unknown_hacker", "SomeRandomPassword12345!", users_db)
        print(f"Вхід для 'unknown_hacker' -> {'УСПІШНО' if res3 else 'ВІДМОВЛЕНО'}")

        # Тест 4: Перевірка роботи власного винятку ValidationError
        print("\nТест 4 (Валідація помилки короткого пароля):")
        generate_hash("123", PERSONAL_SALT)

    except FileNotFoundError as e:
        print(f"\n[ПОМИЛКА КЛАСУ FileNotFoundError]: Файл не знайдено! {e}")
    except PermissionError as e:
        print(f"\n[ПОМИЛКА КЛАСУ PermissionError]: Немає прав доступу! {e}")
    except OSError as e:
        print(f"\n[ПОМИЛКА КЛАСУ IOError]: Помилка роботи з диском! {e}")
    except ValidationError as e:
        print(f"\n[ПОМИЛКА КЛАСУ ValidationError]: Безпека пароля! {e}")
    except ValueError as e:
        print(f"\n[ПОМИЛКА КЛАСУ ValueError]: Передано некоректне значення! {e}")
    except Exception as e:
        print(f"\n[НЕПЕРЕДБАЧЕНА ПОМИЛКА]: {e}")


if __name__ == "__main__":
    main()
