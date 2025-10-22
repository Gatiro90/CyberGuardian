import sqlite3
from datetime import datetime

DB_FILE = "cyberguardian_history.db"

def init_db():
    """Crée la table si elle n'existe pas encore."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            score INTEGER,
            secure BOOLEAN,
            date TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_scan(url, score, secure):
    """Ajoute un enregistrement à l'historique."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, score, secure, date) VALUES (?, ?, ?, ?)", 
              (url, score, secure, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_scans(limit=20):
    """Récupère les derniers scans."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT url, score, secure, date FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def clear_scans():
    """Efface tout l’historique."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
