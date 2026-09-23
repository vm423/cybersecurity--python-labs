import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print(
    f"Лабораторну роботу виконує: {STUDENT_NAME}, група {GROUP_NAME}, варіант {VARIANT_NUMBER}"
)
