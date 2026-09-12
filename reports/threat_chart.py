import matplotlib.pyplot as plt
import sqlite3

conn = sqlite3.connect("../database/prober.db")
cursor = conn.cursor()

cursor.execute("SELECT threat_level, COUNT(*) FROM threats GROUP BY threat_level")
data = cursor.fetchall()

labels = [row[0] for row in data]
sizes = [row[1] for row in data]

plt.pie(sizes, labels=labels, autopct="%1.1f%%")
plt.title("ProbeR Threat Severity Distribution")

plt.savefig("threat_chart.png")

print("Chart saved successfully!")

conn.close()
