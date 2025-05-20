# app.py (Vulnerable code)

import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # WARNING: Vulnerable to SQL Injection!
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))

    result = cursor.fetchone()

    if result:
        print("Login successful!")
    else:
        print("Login failed!")

if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")
    login(username, password)
