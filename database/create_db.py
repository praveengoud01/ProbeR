import sqlite3

conn = sqlite3.connect("prober.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    destination_ip TEXT,
    threat_level TEXT
)
""")

conn.commit()
conn.close()

print("ProbeR Database Created Successfully!")
