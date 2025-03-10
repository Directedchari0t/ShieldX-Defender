import sqlite3
import os
from datetime import datetime

def initialize_database():
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            details TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_scan_result(file_path, file_hash, status, details):
    conn = sqlite3.connect('scan_results.db')
    cursor = conn.cursor()

    # Check if the file is already in the database
    cursor.execute("SELECT * FROM scans WHERE file_hash = ?", (file_hash,))
    existing_entry = cursor.fetchone()

    if not existing_entry:
        cursor.execute(
            "INSERT INTO scans (filename, file_hash, status, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            (os.path.basename(file_path), file_hash, status, details, datetime.now())
        )
        conn.commit()

    conn.close()
