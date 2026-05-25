"""
MCOGAN+ Flask Backend  —  with Live Monitor SSE support
Fixed: correct label classes, malware category enrichment, proper confidence
"""

import os
import json
import queue
import tempfile
import traceback
import numpy as np
import pickle

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS

USE_SHAP = False

FEATURE_NAMES = [
    "File Size",
    "Entropy Score",
    "Section Count",
    "API Call Count",
    "Import Table Size",
]

MODEL_PATH   = os.getenv("MODEL_PATH",   "model.pkl")
ENCODER_PATH = os.getenv("ENCODER_PATH", "label_encoder.pkl")

# ── Load artefacts ────────────────────────────────────────────────────────────
try:
    model = pickle.load(open(MODEL_PATH, "rb"))
    le    = pickle.load(open(ENCODER_PATH, "rb"))
except FileNotFoundError as e:
    raise SystemExit(f"[ERROR] Model artefact not found: {e}\nRun train_model.py first.") from e

print(f"[INFO] Loaded model type: {type(model).__name__}")
print(f"[INFO] Label classes: {list(le.classes_)}")

# ── Re-sanitise model if it is an old XGBoost pkl ────────────────────────────
def _sanitise_and_reload(mdl):
    import xgboost as xgb
    booster = mdl.get_booster() if hasattr(mdl, "get_booster") else mdl
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = f.name
    try:
        booster.save_model(tmp)
        with open(tmp, "r", encoding="utf-8") as f:
            mj = json.load(f)
        param = mj["learner"]["learner_model_param"]
        bs = param.get("base_score", "0.5")
        try:
            float(bs)
        except (ValueError, TypeError):
            scalar = str(float(str(bs).strip("[]").split(",")[0].strip()))
            param["base_score"] = scalar
            print(f"[INFO] base_score patched -> {scalar}")
        for attr in ("best_iteration", "best_ntree_limit"):
            val_raw = param.get(attr)
            if val_raw is not None:
                try:
                    val = int(str(val_raw), 0)
                    if val < 0 or val > 0x7FFFFFFF:
                        raise ValueError("sentinel")
                    param[attr] = str(val)
                except (ValueError, TypeError):
                    print(f"[INFO] {attr} corrupt ({val_raw!r}) — removed")
                    del param[attr]
        mj["learner"]["learner_model_param"] = param
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(mj, f)
        clean = xgb.Booster()
        clean.load_model(tmp)
        print("[INFO] Model re-serialised cleanly.")
        return clean
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

_clean_booster = _sanitise_and_reload(model)

# ── SHAP ──────────────────────────────────────────────────────────────────────
explainer = None
if USE_SHAP:
    try:
        import shap
        explainer = shap.TreeExplainer(_clean_booster)
        print("[INFO] SHAP ready.")
    except Exception as exc:
        print(f"[WARN] SHAP failed: {exc}")

# ── Malware category enrichment ───────────────────────────────────────────────
# Since the model only predicts Benign vs Malware, we use feature heuristics
# to give a more descriptive category label for malicious files.
def _enrich_malware_category(features_2d: np.ndarray) -> str:
    """
    Returns a descriptive malware category based on feature heuristics.
    Called only when prediction == 'Malware'.
    Features: [file_size, entropy, sections, api_calls, import_size]
    """
    file_size   = float(features_2d[0][0])
    entropy     = float(features_2d[0][1])
    sections    = float(features_2d[0][2])
    api_calls   = float(features_2d[0][3])
    import_size = float(features_2d[0][4])

    # High entropy + very few imports = packed/encrypted malware
    if entropy >= 7.0 and import_size <= 10:
        return "Packed Malware"

    # High entropy alone = encrypted payload (ransomware signature)
    if entropy >= 7.2:
        return "Ransomware"

    # Many suspicious API calls = active threat (trojan/spyware behaviour)
    if api_calls >= 15:
        return "Trojan"

    # Very small file + low imports = dropper that downloads real payload
    if file_size <= 50000 and import_size <= 20:
        return "Dropper"

    # Abnormally few sections + moderate entropy = packer/obfuscator
    if sections <= 2 and entropy >= 5.5:
        return "Obfuscated Malware"

    # High import count = uses many Windows APIs, typical of spyware/adware
    if import_size >= 200:
        return "Spyware"

    # Large file with many sections = worm / complex malware
    if file_size >= 5_000_000 and sections >= 8:
        return "Worm"

    # Default
    return "Malware"

# ── Feature importance ────────────────────────────────────────────────────────
def _xgb_importance(features_2d: np.ndarray) -> list:
    scores   = _clean_booster.get_score(importance_type="gain")
    n        = len(FEATURE_NAMES)
    gains    = np.array([scores.get(f"f{i}", 0.0) for i in range(n)], dtype=float)
    weighted = gains * np.abs(features_2d[0])
    total    = weighted.sum() or 1.0
    return [
        {"name": FEATURE_NAMES[i], "value": round(float(weighted[i]), 4),
         "pct": round(float(weighted[i] / total * 100), 1)}
        for i in range(n)
    ]

def build_explanation(features_2d: np.ndarray) -> list:
    if explainer is not None:
        try:
            sv = explainer.shap_values(features_2d)
            abs_vals = np.max([np.abs(s) for s in sv], axis=0).flatten() \
                       if isinstance(sv, list) else np.abs(sv).flatten()
            n     = min(len(abs_vals), len(FEATURE_NAMES))
            total = abs_vals[:n].sum() or 1.0
            return [{"name": FEATURE_NAMES[i], "value": round(float(abs_vals[i]), 4),
                     "pct": round(float(abs_vals[i] / total * 100), 1)} for i in range(n)]
        except Exception as exc:
            print(f"[WARN] SHAP error: {exc}")
    return _xgb_importance(features_2d)

# ── Prediction ────────────────────────────────────────────────────────────────
def _predict(features_2d: np.ndarray):
    import xgboost as xgb

    print(f"[DEBUG] Feature vector: {features_2d[0].tolist()}")

    dmat  = xgb.DMatrix(features_2d)
    proba = _clean_booster.predict(dmat)

    # Binary classification: output is shape (1,) — a single probability for class 1
    # Multiclass: output is shape (1, n_classes)
    n_classes = len(le.classes_)

    if proba.ndim == 1 and n_classes == 2:
        # Binary output: proba[0] = P(class_1 = Malware)
        p_malware = float(proba[0])
        p_benign  = 1.0 - p_malware
        pred_idx  = 1 if p_malware >= 0.5 else 0
        confidence = p_malware * 100 if pred_idx == 1 else p_benign * 100
        row = np.array([p_benign, p_malware])
    else:
        # Multiclass
        if proba.ndim == 1:
            proba = proba.reshape(1, -1)
        row        = proba[0][:n_classes]
        pred_idx   = int(np.argmax(row))
        confidence = float(row[pred_idx] * 100)

    # Decode the base label ("Benign" or "Malware")
    base_label = str(le.inverse_transform([pred_idx])[0])

    # If malicious, enrich with a descriptive category
    if base_label.lower() != "benign":
        label = _enrich_malware_category(features_2d)
    else:
        label = "Benign"

    print(f"[DEBUG] Prediction: {label} ({confidence:.1f}%)")

    class_probs = [
        {"family": str(le.inverse_transform([i])[0]), "pct": round(float(p * 100), 1)}
        for i, p in enumerate(row)
    ]
    class_probs.sort(key=lambda x: x["pct"], reverse=True)

    return label, confidence, class_probs

# ── SSE broadcast ─────────────────────────────────────────────────────────────
_sse_clients: list[queue.Queue] = []

def _broadcast(event_name: str, data: dict):
    payload = f"event: {event_name}\ndata: {json.dumps(data)}\n\n"
    dead = []
    for q in _sse_clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)
    for q in dead:
        _sse_clients.remove(q)

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/events", methods=["GET"])
def events():
    client_q: queue.Queue = queue.Queue(maxsize=100)
    _sse_clients.append(client_q)

    def stream():
        try:
            yield "event: monitor_status\ndata: {\"active\": true}\n\n"
            while True:
                try:
                    msg = client_q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            if client_q in _sse_clients:
                _sse_clients.remove(client_q)

    return Response(
        stream_with_context(stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )

@app.route("/monitor_event", methods=["POST"])
def monitor_event():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Empty payload"}), 400
    _broadcast("scan_result", data)
    status = "MALICIOUS" if data.get("is_malicious") else "BENIGN"
    print(f"[MONITOR] {data.get('filename','?')} -> {status} ({data.get('confidence',0):.1f}%)")
    return jsonify({"ok": True})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "sse_clients": len(_sse_clients)})

@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(force=True, silent=True)
    if not payload or "features" not in payload:
        return jsonify({"error": "Missing 'features' in request body."}), 400

    raw = payload["features"]
    if not isinstance(raw, list) or len(raw) != len(FEATURE_NAMES):
        return jsonify({
            "error": f"Expected {len(FEATURE_NAMES)} features, got {len(raw) if isinstance(raw, list) else '?'}."
        }), 400

    try:
        features = np.array(raw, dtype=float).reshape(1, -1)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": f"Invalid feature values: {exc}"}), 400

    if np.all(features == 0):
        print("[WARN] All-zero feature vector received — returning safe default.")
        return jsonify({
            "prediction":    "Unknown",
            "confidence":    0.0,
            "is_malicious":  False,
            "probabilities": [],
            "shap":          [],
            "warning":       "Could not extract meaningful features from this file.",
        })

    try:
        label, confidence, class_probs = _predict(features)
    except Exception as exc:
        print(f"[ERROR] Prediction failed:\n{traceback.format_exc()}")
        return jsonify({"error": f"Prediction failed: {exc}"}), 500

    explanation = build_explanation(features)

    return jsonify({
        "prediction":    label,
        "confidence":    round(confidence, 2),
        "is_malicious":  label.lower() != "benign",
        "probabilities": class_probs[:6],
        "shap":          explanation,
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
