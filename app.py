import os, re, json, time, uuid, threading
from collections import deque
def _env(path):  # minimal .env loader: KEY=value lines, real env vars win
    try:
        for l in open(path):
            l = l.strip()
            if "=" in l and not l.startswith("#"):
                k, v = l.split("=", 1); k = k.replace("export ", "").strip()
                if not os.environ.get(k): os.environ[k] = v.strip().strip("\"'")
    except FileNotFoundError: pass
_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
from flask import Flask, render_template, request, jsonify, Response, abort
import intel
app = Flask(__name__); JOBS, ORDER, LOCK, HITS = {}, [], threading.Lock(), {}
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

@app.after_request
def hardening(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": CSP})
    if request.path.startswith(("/api/", "/report/")): r.headers["Cache-Control"] = "no-store"
    return r

def throttled(n=30, window=60):  # simple per-client sliding window so a stray loop can't burn the API quotas
    q, now = HITS.setdefault(request.remote_addr, deque()), time.time()
    while q and now - q[0] > window: q.popleft()
    if len(q) >= n: return True
    q.append(now); return False

def run(jid):
    j = JOBS[jid]
    try: j["result"] = intel.investigate(j["target"], j["log"].append)
    except Exception as e: j["error"] = f"{type(e).__name__}: {e}"
    j["done"] = True

@app.get("/")
def index(): return render_template("index.html")

@app.get("/api/status")
def status():  # reports only whether a key is configured - never the key itself
    return jsonify(version=intel.VER, keys={k: bool(os.getenv(k)) for k in intel.KEYS}, cache_entries=len(intel.CACHE), vt_rpm=intel.VTL.rpm)

@app.post("/api/scan")
def scan():
    t = (request.get_json(silent=True) or {}).get("target", "").strip()
    if not t or len(t) > 2048 or not re.fullmatch(r"[^\s<>\"'`\\]+", t): return jsonify(error="invalid target"), 400
    if throttled(): return jsonify(error="too many scans - wait a minute"), 429
    jid = uuid.uuid4().hex[:10]
    with LOCK:
        JOBS[jid] = {"target": t, "log": [], "done": False, "result": None, "error": None}; ORDER.insert(0, jid)
        for old in ORDER[40:]: JOBS.pop(old, None)
        del ORDER[40:]
    threading.Thread(target=run, args=(jid,), daemon=True).start()
    return jsonify(id=jid)

@app.get("/api/job/<jid>")
def job(jid):
    j = JOBS.get(jid) or abort(404); s = request.args.get("since", 0, int)
    return jsonify(log=j["log"][s:], done=j["done"], result=j["result"], error=j["error"])

@app.get("/api/history")
def history():
    return jsonify([{"id": i, "target": JOBS[i]["target"], "score": (JOBS[i]["result"] or {}).get("score"),
                     "level": (JOBS[i]["result"] or {}).get("level")} for i in list(ORDER) if i in JOBS and JOBS[i]["done"]])

@app.get("/report/<jid>/<fmt>")
def report(jid, fmt):
    j = JOBS.get(jid) or abort(404); r = j["result"] or abort(404)
    name = re.sub(r"[^\w.-]", "_", j["target"])[:60]
    body, mime, ext = {"md": (lambda: intel.report_md(r), "text/markdown", "md"),
                       "json": (lambda: json.dumps(r, indent=1, default=str), "application/json", "json"),
                       "csv": (lambda: intel.iocs_csv(r), "text/csv", "iocs.csv"),
                       "stix": (lambda: json.dumps(intel.stix(r), indent=1), "application/stix+json", "stix.json")}.get(fmt) or abort(404)
    return Response(body(), mimetype=mime, headers={"Content-Disposition": f"attachment; filename=threatlens-{name}.{ext}"})

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), threaded=True)
