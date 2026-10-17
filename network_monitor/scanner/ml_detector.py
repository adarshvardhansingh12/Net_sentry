"""
ml_detector.py
Machine-learning anomaly detection that runs next to the rule-based checks
in detector.py.

Model: Isolation Forest (scikit-learn), one separate model per device.

Why this model:
  * Unsupervised - it needs no labelled attack data. It learns what "normal"
    looks like from each device's own history and flags readings that do not
    fit. (We have no labelled data from our own network.)
  * It looks at several features together, so it can flag a reading where no
    single value crosses a fixed threshold but the combination is unusual.
  * Tree based, so features need no scaling.

Features per 30-second scan cycle, per device:
    [bytes, packets, unique_dests, hour_of_day]

Nothing is predicted until a device has MIN_SAMPLES readings, and devices
with no observed traffic at all are skipped (nothing to learn from).
"""

from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

import db

# ---- Tunable parameters ----
MIN_SAMPLES = 50        # readings needed before predicting (50 cycles = about 25 minutes)
HISTORY_LIMIT = 500     # use at most this many recent readings per device
CONTAMINATION = 0.01    # assumed share of past readings that were already unusual.
                        # Tested on synthetic data: 0.05 gave 5-11% false alerts,
                        # 0.01 gave 1-3%. Re-tune on real baseline data.
N_ESTIMATORS = 100      # number of random trees
RETRAIN_EVERY = 10      # retrain after this many new readings, not every cycle
COOLDOWN_MINUTES = 10   # at most one ML alert per device in this window

_models = {}            # mac -> (trained model, number of readings it was trained on)
_last_alert = {}        # mac -> time of the last ML alert for that device


def _get_model(mac, history):
    """Return the cached model for this device, retraining when enough new data arrived."""
    n = len(history)
    cached = _models.get(mac)
    if cached and n - cached[1] < RETRAIN_EVERY:
        return cached[0]
    model = IsolationForest(
        n_estimators=N_ESTIMATORS, contamination=CONTAMINATION, random_state=42
    )
    model.fit(np.array(history, dtype=float))
    _models[mac] = (model, n)
    return model


def score(mac, current):
    """
    Score one reading [bytes, packets, unique_dests, hour] for a device.
    Returns {"ready": False, "reason": ...} when we cannot judge yet, or
    {"ready": True, "is_anomaly": bool, "score": float} (lower = more unusual).
    """
    history = db.get_feature_history(mac, HISTORY_LIMIT)
    if len(history) < MIN_SAMPLES:
        return {"ready": False, "reason": f"only {len(history)} readings, need {MIN_SAMPLES}"}
    if all(row[0] == 0 and row[1] == 0 for row in history):
        return {"ready": False, "reason": "no traffic observed for this device"}

    model = _get_model(mac, history)
    x = np.array([current], dtype=float)
    return {
        "ready": True,
        "is_anomaly": bool(model.predict(x)[0] == -1),   # -1 = anomaly, 1 = normal
        "score": float(model.decision_function(x)[0]),
    }


def check_ml_anomaly(mac, ip, features):
    """
    features: {"bytes": int, "packets": int, "dests": int} for this cycle.
    Saves an ML_ANOMALY alert and returns its message if the model flags
    the reading; returns None otherwise.
    """
    now = datetime.now()
    last = _last_alert.get(mac)
    if last and now - last < timedelta(minutes=COOLDOWN_MINUTES):
        return None  # already alerted for this device recently

    hour = now.hour
    current = [features["bytes"], features["packets"], features["dests"], hour]
    result = score(mac, current)
    if result.get("ready") and result["is_anomaly"]:
        _last_alert[mac] = now
        message = (
            f"ML model flagged unusual behavior from {mac} ({ip}): "
            f"{features['bytes']} bytes, {features['packets']} packets, "
            f"{features['dests']} destinations at hour {hour} "
            f"(anomaly score {result['score']:.3f})"
        )
        db.create_alert(mac, ip, "ML_ANOMALY", message)
        return message
    return None
