"""
ProbeR - AI Powered Network Threat Detection System
Main Flask application: wires together auth, dashboard, traffic analysis,
the AI anomaly detector, live monitor, and reporting into one running site.

Run:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000
"""

import csv
import os
import sqlite3
from collections import Counter
from functools import wraps

from flask import (
    Flask, flash, redirect, render_template, request,
    send_file, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

# --- Paths (absolute, so the app runs the same no matter the working dir) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "prober.db")
DATA_PATH = os.path.join(BASE_DIR, "data", "traffic.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "prober_model.pkl")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
REPORT_TXT_PATH = os.path.join(REPORTS_DIR, "security_report.txt")
REPORT_CSV_PATH = os.path.join(REPORTS_DIR, "threats_export.csv")
CHART_PATH = os.path.join(REPORTS_DIR, "threat_chart.png")

SAFE_PORTS = [80, 443, 53]

app = Flask(__name__)
app.secret_key = os.environ.get("PROBER_SECRET_KEY", os.urandom(24))

# --- Auth config: override via environment variables in production ---
ADMIN_USERNAME = os.environ.get("PROBER_ADMIN_USER", "admin")
_default_password = os.environ.get("PROBER_ADMIN_PASS", "prober123")
ADMIN_PASSWORD_HASH = generate_password_hash(_default_password)

if "PROBER_ADMIN_PASS" not in os.environ:
    print(
        "[ProbeR] WARNING: using the default demo password. "
        "Set PROBER_ADMIN_USER / PROBER_ADMIN_PASS before deploying anywhere real."
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            threat_level TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def get_db():
    return sqlite3.connect(DB_PATH)


def read_traffic_rows():
    """Read data/traffic.csv as raw string rows: [src_ip, dst_ip, src_port, dst_port, service, protocol]."""
    if not os.path.exists(DATA_PATH):
        return []
    rows = []
    with open(DATA_PATH, "r", newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 6:
                rows.append(row)
    return rows


# ---------------------------------------------------------------- Auth ----

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["logged_in"] = True
            session["username"] = username
            flash("Login successful. Welcome to ProbeR.", "ok")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------- Dashboard ----

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY id DESC")
    threats = cursor.fetchall()
    conn.close()

    total_threats = len(threats)
    high_threats = sum(1 for t in threats if t[3] == "HIGH")
    level_counts = Counter(t[3] for t in threats).most_common()

    top_attacker = None
    if threats:
        dest_counts = Counter(t[2] for t in threats)
        top_attacker = dest_counts.most_common(1)[0]

    return render_template(
        "dashboard.html",
        threats=threats[:20],
        total_threats=total_threats,
        high_threats=high_threats,
        level_counts=level_counts,
        top_attacker=top_attacker,
        model_loaded=os.path.exists(MODEL_PATH),
    )


# ------------------------------------------------------------- Analysis ----

@app.route("/ports")
@login_required
def ports():
    rows = read_traffic_rows()
    if not rows:
        return render_template("ports.html", ports=None, error="No traffic data found in data/traffic.csv yet.")

    port_counter = Counter(row[3] for row in rows)
    return render_template("ports.html", ports=port_counter.most_common(), error=None)


@app.route("/risk")
@login_required
def risk():
    rows = read_traffic_rows()
    if not rows:
        return render_template("risk.html", error="No traffic data found in data/traffic.csv yet.")

    port_counter = Counter()
    for row in rows:
        try:
            port_counter[int(row[3])] += 1
        except (ValueError, IndexError):
            pass

    risk_score = sum(10 for port in port_counter if port not in SAFE_PORTS)
    if risk_score <= 20:
        status = "SAFE"
    elif risk_score <= 50:
        status = "WARNING"
    else:
        status = "HIGH RISK"

    return render_template("risk.html", risk_score=risk_score, status=status, error=None)


# ------------------------------------------------------------ AI Detector ----

def _load_traffic_dataframe():
    import pandas as pd
    if not os.path.exists(DATA_PATH):
        return None
    df = pd.read_csv(
        DATA_PATH, header=None,
        names=["src_ip", "dst_ip", "src_port", "dst_port", "service", "protocol"],
    )
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["protocol"] = pd.to_numeric(df["protocol"], errors="coerce")
    return df


@app.route("/ai")
@login_required
def ai_detector():
    model_loaded = os.path.exists(MODEL_PATH)
    results, error = None, None

    df = _load_traffic_dataframe()
    if df is None or df.empty:
        error = "No traffic data found in data/traffic.csv yet."
    elif not model_loaded:
        error = None  # prompt to train, handled in template
    else:
        import joblib
        model = joblib.load(MODEL_PATH)
        features = df[["dst_port", "protocol"]].fillna(0)
        predictions = model.predict(features)
        results = [
            {
                "src": row.src_ip, "dst": row.dst_ip,
                "port": row.dst_port, "protocol": row.protocol,
                "anomaly": pred == -1,
            }
            for row, pred in zip(df.itertuples(), predictions)
        ]

    return render_template("ai.html", model_loaded=model_loaded, results=results, error=error)


@app.route("/ai/train", methods=["POST"])
@login_required
def ai_train():
    df = _load_traffic_dataframe()
    if df is None or df.empty:
        flash("Can't train: no traffic data in data/traffic.csv yet.", "error")
        return redirect(url_for("ai_detector"))

    from sklearn.ensemble import IsolationForest
    import joblib

    features = df[["dst_port", "protocol"]].fillna(0)
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(features)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    flash("Model trained and saved successfully.", "ok")
    return redirect(url_for("ai_detector"))


# -------------------------------------------------------------- Monitor ----

@app.route("/monitor")
@login_required
def monitor():
    return render_template("monitor.html")


# -------------------------------------------------------------- Capture ----

@app.route("/capture")
@login_required
def capture_info():
    return render_template("capture.html")


# -------------------------------------------------------------- Reports ----

@app.route("/reports")
@login_required
def reports():
    return render_template(
        "reports.html",
        report_exists=os.path.exists(REPORT_TXT_PATH),
        csv_exists=os.path.exists(REPORT_CSV_PATH),
        chart_exists=os.path.exists(CHART_PATH),
    )


@app.route("/reports/generate", methods=["POST"])
@login_required
def generate_report():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats")
    rows = cursor.fetchall()
    conn.close()

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(REPORT_TXT_PATH, "w") as report:
        report.write("=== ProbeR Security Report ===\n\n")
        for row in rows:
            report.write(str(row) + "\n")

    flash("Report generated successfully.", "ok")
    return redirect(url_for("reports"))


@app.route("/reports/download")
@login_required
def download_report():
    return send_file(REPORT_TXT_PATH, as_attachment=True)


@app.route("/reports/export", methods=["POST"])
@login_required
def export_csv():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats")
    rows = cursor.fetchall()
    conn.close()

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(REPORT_CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Source_IP", "Destination_IP", "Threat_Level"])
        writer.writerows(rows)

    flash("CSV exported successfully.", "ok")
    return redirect(url_for("reports"))


@app.route("/reports/csv")
@login_required
def download_csv():
    return send_file(REPORT_CSV_PATH, as_attachment=True)


@app.route("/reports/chart", methods=["POST"])
@login_required
def generate_chart():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT threat_level, COUNT(*) FROM threats GROUP BY threat_level")
    data = cursor.fetchall()
    conn.close()

    if not data:
        flash("No threats to chart yet.", "error")
        return redirect(url_for("reports"))

    labels = [row[0] for row in data]
    sizes = [row[1] for row in data]

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct="%1.1f%%")
    ax.set_title("ProbeR Threat Severity Distribution")

    os.makedirs(REPORTS_DIR, exist_ok=True)
    fig.savefig(CHART_PATH)
    plt.close(fig)

    flash("Chart generated successfully.", "ok")
    return redirect(url_for("reports"))


@app.route("/reports/chart.png")
@login_required
def view_chart():
    return send_file(CHART_PATH, mimetype="image/png")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
