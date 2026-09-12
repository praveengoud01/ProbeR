import sqlite3

conn = sqlite3.connect("../database/prober.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM threats")
rows = cursor.fetchall()

report = open("security_report.txt", "w")

report.write("=== ProbeR Security Report ===\n\n")

for row in rows:
    report.write(str(row) + "\n")

report.close()

print("Report Generated Successfully!")
