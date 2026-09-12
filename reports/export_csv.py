import sqlite3
import csv

conn = sqlite3.connect("../database/prober.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM threats")
rows = cursor.fetchall()

with open("threats_export.csv", "w", newline="") as f:
    writer = csv.writer(f)

    writer.writerow([
        "ID",
        "Source_IP",
        "Destination_IP",
        "Threat_Level"
    ])

    writer.writerows(rows)

print("Threats exported successfully!")

conn.close()
