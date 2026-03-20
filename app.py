"""
Pentest Assistant — AI-powered penetration testing helper.
For authorized security testing only.
"""
import os
import uuid
import traceback
from datetime import datetime
from threading import Thread

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, Response, session, send_from_directory

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pentest-dev-secret")

# In-memory session store: {session_id: {target, port, recon, findings, ...}}
_sessions: dict[str, dict] = {}
# Background job status: {job_id: {status, result, error}}
_jobs: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_session(target: str, port: int, scan_type: str = "full") -> str:
    sid = str(uuid.uuid4())
    _sessions[sid] = {
        "id": sid,
        "target": target,
        "port": port,
        "scan_type": scan_type,
        "created_at": datetime.utcnow().isoformat(),
        "recon": {},
        "attack_surface": [],
        "findings": [],
        "notes": "",
    }
    return sid


def _run_recon_bg(job_id: str, sid: str, target: str, ports: list[int], scan_type: str):
    try:
        from modules.recon import run_recon
        _jobs[job_id]["status"] = "running"
        result = run_recon(target, ports=ports, scan_type=scan_type)
        _sessions[sid]["recon"] = result

        # Auto-suggest attack surface
        from modules.payload_crafter import get_attack_surface
        _sessions[sid]["attack_surface"] = get_attack_surface(result.get("open_ports", []))

        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
    except Exception as e:
        traceback.print_exc()
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(e)


def _run_craft_bg(job_id: str, sid: str, target: str, port: int,
                  category: str, attack_type: str, context: str, service_info: str):
    try:
        from modules.payload_crafter import craft_payloads
        _jobs[job_id]["status"] = "running"
        result = craft_payloads(target, port, category, attack_type, context, service_info)
        result["generated_at"] = datetime.utcnow().isoformat()
        _sessions[sid]["findings"].append(result)
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
    except Exception as e:
        traceback.print_exc()
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(e)


# ---------------------------------------------------------------------------
# Routes — UI
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    return jsonify([
        {"id": s["id"], "target": s["target"], "port": s["port"],
         "created_at": s["created_at"], "findings_count": len(s["findings"])}
        for s in _sessions.values()
    ])


@app.route("/api/sessions", methods=["POST"])
def create_session():
    data = request.json or {}
    target = data.get("target", "").strip()
    port = int(data.get("port", 80))
    scan_type = data.get("scan_type", "quick")

    if not target:
        return jsonify({"error": "target is required"}), 400

    sid = _new_session(target, port, scan_type)
    return jsonify({"session_id": sid})


@app.route("/api/sessions/<sid>", methods=["GET"])
def get_session(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404
    return jsonify(s)


@app.route("/api/sessions/<sid>", methods=["DELETE"])
def delete_session(sid: str):
    _sessions.pop(sid, None)
    return jsonify({"ok": True})


@app.route("/api/sessions/<sid>/notes", methods=["PUT"])
def update_notes(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404
    s["notes"] = request.json.get("notes", "")
    return jsonify({"ok": True})


# ---- Recon ----

@app.route("/api/sessions/<sid>/recon", methods=["POST"])
def start_recon(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404

    data = request.json or {}
    scan_type = data.get("scan_type", s.get("scan_type", "quick"))
    custom_ports_raw = data.get("ports", "")

    custom_ports = []
    if custom_ports_raw:
        for p in str(custom_ports_raw).split(","):
            p = p.strip()
            if p.isdigit():
                custom_ports.append(int(p))

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "pending", "result": None, "error": None}

    t = Thread(
        target=_run_recon_bg,
        args=(job_id, sid, s["target"], custom_ports or None, scan_type),
        daemon=True,
    )
    t.start()
    return jsonify({"job_id": job_id})


# ---- Payload Crafting ----

@app.route("/api/sessions/<sid>/craft", methods=["POST"])
def craft(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404

    data = request.json or {}
    port = int(data.get("port", s["port"]))
    category = data.get("category", "web")
    attack_type = data.get("attack_type", "sqli")
    context = data.get("context", "")

    # Build service_info from recon
    open_ports = s.get("recon", {}).get("open_ports", [])
    service_info = ""
    for p in open_ports:
        if p["port"] == port:
            service_info = f"{p.get('service', '')} {p.get('version', '')} {p.get('banner', '')}".strip()
            break

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "pending", "result": None, "error": None}

    t = Thread(
        target=_run_craft_bg,
        args=(job_id, sid, s["target"], port, category, attack_type, context, service_info),
        daemon=True,
    )
    t.start()
    return jsonify({"job_id": job_id})


@app.route("/api/sessions/<sid>/findings", methods=["GET"])
def get_findings(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404
    return jsonify(s.get("findings", []))


@app.route("/api/sessions/<sid>/findings/<int:idx>", methods=["DELETE"])
def delete_finding(sid: str, idx: int):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404
    findings = s.get("findings", [])
    if 0 <= idx < len(findings):
        findings.pop(idx)
    return jsonify({"ok": True})


# ---- Jobs ----

@app.route("/api/jobs/<job_id>", methods=["GET"])
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job)


# ---- Report ----

@app.route("/api/sessions/<sid>/report", methods=["GET"])
def get_report(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404
    try:
        from modules.reporter import generate_pdf
        pdf_bytes = generate_pdf(s)
        if not pdf_bytes:
            return jsonify({"error": "PDF generation returned empty output"}), 500
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="pentest-{s["target"]}-{sid[:6]}.pdf"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except ImportError:
        return jsonify({"error": "fpdf2 not installed. Run: pip install fpdf2"}), 500
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500


# ---- Attack Surface ----

@app.route("/api/sessions/<sid>/attack-surface", methods=["GET"])
def get_attack_surface(sid: str):
    s = _sessions.get(sid)
    if not s:
        return jsonify({"error": "session not found"}), 404
    return jsonify(s.get("attack_surface", []))


# ---- Manual payload craft (no session) ----

@app.route("/api/craft/quick", methods=["POST"])
def quick_craft():
    """One-off payload craft without a persistent session."""
    data = request.json or {}
    target = data.get("target", "")
    port = int(data.get("port", 80))
    category = data.get("category", "web")
    attack_type = data.get("attack_type", "sqli")
    context = data.get("context", "")
    service_info = data.get("service_info", "")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "pending", "result": None, "error": None}

    # For quick craft we use a throwaway session store
    sid = _new_session(target, port)

    t = Thread(
        target=_run_craft_bg,
        args=(job_id, sid, target, port, category, attack_type, context, service_info),
        daemon=True,
    )
    t.start()
    return jsonify({"job_id": job_id})


@app.route("/oscp")
def oscp():
    return send_from_directory(".", "oscp.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
