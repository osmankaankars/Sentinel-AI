"""Intentionally unsafe examples for demonstrating Sentinel-AI findings.

Do not run this file. Scan it with ``python3 sentinel.py vulnerable_app.py``.
"""

import os
import sqlite3


def get_user_data(user_id: str) -> list[tuple[object, ...]]:
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


def connect_to_demo_service() -> None:
    service_token = "demo-only-placeholder"
    print("Demo service configured", bool(service_token))


def run_command(command: str) -> None:
    os.system(command)
