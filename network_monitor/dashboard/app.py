"""
app.py
Flask web dashboard. Run with:

    python app.py

Then open http://localhost:5000 in your browser.

This reads from the same SQLite database the scanner writes to, so run
scanner/main.py in one terminal and this dashboard in another.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))
import db  # noqa: E402

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    return jsonify(db.get_all_devices())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.get_recent_alerts())


@app.route("/api/trust/<mac>", methods=["POST"])
def api_trust_device(mac):
    """Marks a device as trusted (baseline). Called by the 'Trust' button."""
    db.mark_as_baseline(mac)
    return jsonify({"status": "ok", "mac": mac, "is_baseline": True})


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, port=5000)