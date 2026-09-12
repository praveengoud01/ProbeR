import sqlite3

conn = sqlite3.connect("../database/prober.db")
cursor = conn.cursor()

cursor.execute("""
SELECT destination_ip, COUNT(*)
FROM threats
GROUP BY destination_ip
ORDER BY COUNT(*) DESC
LIMIT 1
""")

result = cursor.fetchone()

print("=== ProbeR Top Attacker Analysis ===")

if result:
    print("Most Targeted IP:", result[0])
    print("Threat Count:", result[1])
else:
    print("No threats found")

conn.close()
