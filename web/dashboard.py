from flask import Flask, render_template
import sqlite3
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def dashboard():
    conn = sqlite3.connect('scan_results.db')
    conn.row_factory = sqlite3.Row
    scans = conn.execute('''
        SELECT filename, status, timestamp, details 
        FROM scans 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''').fetchall()
    conn.close()
    return render_template('dashboard.html', scans=scans)
