"""
Servir a página falsa de login, registar metadados,
rastrear cliques de email e redirecionar para a página de aviso.
"""

import json
import os

import requests as req
from flask import Flask, redirect, render_template, request

from logger import CAMPAIGN_PATH, CAPTURES_PATH, CLICKS_PATH, log_capture, log_click

# IPs de redes privadas/loopback que a ip-api.com não consegue geolocali­zar
_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "::1",
)


def _geolocate(ip: str) -> dict:
    """Consulta ip-api.com e devolve dados de localização. Nunca lança exceção."""
    if not ip or any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return {"country": "Rede Local", "countryCode": "LAN", "city": "—", "isp": "—"}
    try:
        resp = req.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,lat,lon,timezone"},
            timeout=2,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country":     data.get("country", "—"),
                "countryCode": data.get("countryCode", "—"),
                "regionName":  data.get("regionName", "—"),
                "city":        data.get("city", "—"),
                "isp":         data.get("isp", "—"),
                "org":         data.get("org", "—"),
                "lat":         data.get("lat"),
                "lon":         data.get("lon"),
                "timezone":    data.get("timezone", "—"),
            }
    except Exception:
        pass
    return {}


def _flag_emoji(country_code: str) -> str:
    """Converte código ISO-3166-1 alpha-2 em emoji de bandeira (ex: 'PT' → '🇵🇹')."""
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

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
    geo = _geolocate(ip)
    log_capture(email=email, ip=ip, user_agent=user_agent, track_token=track_token, geo=geo)
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

    # Enriquecer com emoji de bandeira para apresentação no template
    for c in recent_captures:
        code = (c.get("geo") or {}).get("countryCode", "")
        c["flag"] = _flag_emoji(code)

    return render_template("dashboard.html", stats=stats, captures=recent_captures, campaign=campaign)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
