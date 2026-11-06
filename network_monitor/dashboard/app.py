"""NetSentry Sentinel Pro Flask dashboard backend.

Run this file from the dashboard directory while scanner/main.py is running
in a separate terminal. Both processes use scanner/db.py and the same SQLite DB.
"""

import sys
from pathlib import Path

SCANNER_DIR = Path(__file__).resolve().parent.parent / "scanner"
sys.path.insert(0, str(SCANNER_DIR))

import db  # noqa: E402
from flask import Flask, jsonify, render_template

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
)


def _json_error(message, status=500):
    return jsonify({"error": message}), status


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    """Simple endpoint to confirm the dashboard can reach its database."""
    try:
        conn = db.get_connection()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return jsonify({"status": "ok", "database": "connected"})
    except Exception as exc:
        app.logger.exception("Database health check failed")
        return _json_error(str(exc))


@app.route("/api/devices")
def api_devices():
    """Return devices in the shape expected by the dashboard frontend."""
    try:
        devices = db.get_all_devices()
        conn = db.get_connection()
        try:
            # The devices table stores last_seen but not last_ip. Get the most
            # recently logged IP for each MAC from connection_log instead.
            rows = conn.execute(
                """SELECT c.mac, c.ip
                   FROM connection_log c
                   INNER JOIN (
                       SELECT mac, MAX(id) AS max_id
                       FROM connection_log
                       GROUP BY mac
                   ) latest ON latest.max_id = c.id"""
            ).fetchall()
            last_ip_by_mac = {row["mac"]: row["ip"] for row in rows}
        finally:
            conn.close()

        for device in devices:
            device["last_ip"] = last_ip_by_mac.get(device.get("mac"))
        return jsonify(devices)
    except Exception as exc:
        app.logger.exception("Could not load devices")
        return _json_error(str(exc))


@app.route("/api/alerts")
def api_alerts():
    try:
        return jsonify(db.get_recent_alerts(limit=200))
    except Exception as exc:
        app.logger.exception("Could not load alerts")
        return _json_error(str(exc))


@app.route("/api/traffic")
def api_traffic():
    """Return protocol totals and recent packet metadata for the UI.

    The frontend expects protocol_stats as [{protocol, bytes}], not a dict.
    """
    try:
        raw_stats = db.get_protocol_stats()
        protocol_stats = [
            {"protocol": protocol, "bytes": int(byte_count)}
            for protocol, byte_count in raw_stats.items()
        ]
        recent_packets = db.get_recent_packets(limit=50)
        return jsonify({
            "protocol_stats": protocol_stats,
            "recent_packets": recent_packets,
        })
    except Exception as exc:
        app.logger.exception("Could not load traffic telemetry")
        return _json_error(str(exc))


@app.route("/api/trust/<path:mac>", methods=["POST"])
def api_trust_device(mac):
    try:
        db.mark_as_baseline(mac)
        return jsonify({"status": "ok", "mac": mac, "is_baseline": True})
    except Exception as exc:
        app.logger.exception("Could not trust device %s", mac)
        return _json_error(str(exc))


@app.route("/api/untrust/<path:mac>", methods=["POST"])
def api_untrust_device(mac):
    try:
        conn = db.get_connection()
        try:
            cursor = conn.execute(
                "UPDATE known_devices SET is_baseline = 0 WHERE mac = ?",
                (mac,),
            )
            conn.commit()
            if cursor.rowcount == 0:
                return _json_error("Device not found", 404)
        finally:
            conn.close()
        return jsonify({"status": "ok", "mac": mac, "is_baseline": False})
    except Exception as exc:
        app.logger.exception("Could not untrust device %s", mac)
        return _json_error(str(exc))


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_ack_alert(alert_id):
    try:
        conn = db.get_connection()
        try:
            cursor = conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,),
            )
            conn.commit()
            if cursor.rowcount == 0:
                return _json_error("Alert not found", 404)
        finally:
            conn.close()
        return jsonify({"status": "ok", "id": alert_id, "acknowledged": True})
    except Exception as exc:
        app.logger.exception("Could not acknowledge alert %s", alert_id)
        return _json_error(str(exc))


@app.route("/api/alerts/ack-all", methods=["POST"])
def api_ack_all_alerts():
    try:
        conn = db.get_connection()
        try:
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
            conn.commit()
        finally:
            conn.close()
        return jsonify({"status": "ok", "acknowledged": "all"})
    except Exception as exc:
        app.logger.exception("Could not acknowledge all alerts")
        return _json_error(str(exc))


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Endpoint not found"}), 404


if __name__ == "__main__":
    db.init_db()
    # Debug reloader disabled to avoid starting duplicate dashboard processes.
    app.run(host="127.0.0.1", port=5000, debug=False)

