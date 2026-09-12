from flask import Flask, request

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "prober123"

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            return """
            <html>
            <body style="background:black;color:lime;font-family:Arial;text-align:center;padding:50px;">
            <h1>✅ Login Successful</h1>
            <h2>Welcome to ProbeR Security Center</h2>
            </body>
            </html>
            """

        return """
        <html>
        <body style="background:black;color:red;font-family:Arial;text-align:center;padding:50px;">
        <h1>❌ Invalid Credentials</h1>
        </body>
        </html>
        """

    return """
    <html>
    <body style="background:black;color:lime;font-family:Arial;text-align:center;padding:50px;">

    <h1>🔐 ProbeR Login</h1>

    <form method="POST">

    <p>Username</p>
    <input type="text" name="username">

    <p>Password</p>
    <input type="password" name="password">

    <br><br>

    <input type="submit" value="Login">

    </form>

    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=False)
