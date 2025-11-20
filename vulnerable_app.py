import sqlite3
import os

def get_user_data(user_id):
    # VULNERABILITY 1: SQL Injection via f-string
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def aws_connect():
    # VULNERABILITY 2: Hardcoded Credentials
    aws_key = "AKIAIOSFODNN7EXAMPLE" 
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    print(f"Connecting with {aws_key}...")
    
def run_command(cmd):
    # VULNERABILITY 3: Command Injection
    os.system(cmd)
