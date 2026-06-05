"""
Servir a página falsa de login, registar metadados
e redirecionar para a página de aviso.
"""

from flask import Flask, redirect, render_template, request

from logger import log_capture

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def no_cache_html(response):
    # Impedir cache de HTML no browser
    if response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.route("/", methods=["GET"])
def index():
    # Servir página falsa de login
    return render_template("login.html")


@app.route("/capture", methods=["POST"])
def capture():
    # Receber e registar metadados
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()

    user_agent = request.headers.get("User-Agent", "")
    email = request.form.get("username", "").strip()

    log_capture(email=email, ip=ip, user_agent=user_agent)
    return redirect("/warning")


@app.route("/warning", methods=["GET"])
def warning():
    # Servir página de aviso
    return render_template("warning.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
