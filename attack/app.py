"""
Servir a página falsa de login, registar metadados,
rastrear cliques de email e redirecionar para a página de aviso.
"""

import json
import os

from flask import Flask, redirect, render_template, request

from logger import CAMPAIGN_PATH, CAPTURES_PATH, CLICKS_PATH, log_capture, log_click

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True


def _read_json(path: str) -> list:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except (json.JSONDecodeError, ValueError):
            return []


@app.after_request
def no_cache_html(response):
    if response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.route("/", methods=["GET"])
def index():
    track_token = request.args.get("token", "")
    return render_template("login.html", track_token=track_token)


@app.route("/track/<token>", methods=["GET"])
def track(token: str):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "")
    log_click(token=token, ip=ip, user_agent=user_agent)
    return redirect(f"/?token={token}")


@app.route("/capture", methods=["POST"])
def capture():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "")
    email = request.form.get("username", "").strip()
    track_token = request.form.get("track_token", "")
    log_capture(email=email, ip=ip, user_agent=user_agent, track_token=track_token)
    return redirect("/warning")


@app.route("/warning", methods=["GET"])
def warning():
    return render_template("warning.html")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    captures = _read_json(CAPTURES_PATH)
    clicks = _read_json(CLICKS_PATH)
    campaign = _read_json(CAMPAIGN_PATH)

    total_sent = len(campaign)
    total_clicks = len(clicks)
    total_captures = len(captures)
    unique_emails = len({c["email"] for c in captures if c.get("email")})
    unique_ips = len({c["ip"] for c in captures if c.get("ip")})

    def rate(num, den):
        return f"{num / den * 100:.0f}%" if den else "—"

    stats = {
        "total_sent": total_sent,
        "total_clicks": total_clicks,
        "total_captures": total_captures,
        "unique_emails": unique_emails,
        "unique_ips": unique_ips,
        "click_rate": rate(total_clicks, total_sent),
        "capture_rate": rate(total_captures, total_sent),
    }

    recent_captures = list(reversed(captures[-50:]))
    return render_template("dashboard.html", stats=stats, captures=recent_captures, campaign=campaign)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
