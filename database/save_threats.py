import sqlite3

conn = sqlite3.connect("prober.db")
cursor = conn.cursor()

source_ip = "10.0.2.15"
destination_ip = "172.64.148.235"
threat_level = "HIGH"

cursor.execute(
    """
    INSERT INTO threats
    (source_ip, destination_ip, threat_level)
    VALUES (?, ?, ?)
    """,
    (source_ip, destination_ip, threat_level)
)

conn.commit()
conn.close()

print("Threat saved successfully!")
