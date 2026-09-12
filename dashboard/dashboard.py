from flask import Flask
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():

    conn = sqlite3.connect("../database/prober.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM threats")
    threats = cursor.fetchall()

    total_threats = len(threats)

    high_threats = 0

    for threat in threats:
        if threat[3] == "HIGH":
            high_threats += 1

    html = f"""
    <html>

    <head>
        <title>ProbeR Security Center</title>
        <meta http-equiv="refresh" content="5">
    </head>

    <body style="background:black;color:lime;font-family:Arial;padding:20px;">

    <h1>🛡 ProbeR Security Center</h1>

    <hr>

    <h2>System Status</h2>

    <p>Database: Online ✅</p>
    <p>AI Engine: Online ✅</p>

    <hr>

    <h2>Threat Analytics</h2>

    <h3>Total Threats Detected: {total_threats}</h3>

    <h3>High Risk Threats: {high_threats}</h3>

    <hr>

    <h2>Recent Threats</h2>
    """

    for threat in threats:
        html += f"""
        <p>
        ID: {threat[0]}
        |
        Source: {threat[1]}
        |
        Destination: {threat[2]}
        |
        Level: {threat[3]}
        </p>
        """

    html += """
    </body>
    </html>
    """

    conn.close()

    return html

app.run(host="0.0.0.0", port=5000)
