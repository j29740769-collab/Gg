import os
import time
import socket
import subprocess
import threading
import collections
import secrets
import zipfile
import tempfile
import shutil
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, Response
import requests
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APPS_DIR = os.path.join(BASE_DIR, "apps")
os.makedirs(APPS_DIR, exist_ok=True)


def render_page(filename, **context):
    """Reads an .html file straight from the same folder as this script — no templates/ subfolder needed."""
    path = os.path.join(BASE_DIR, filename)
    with open(path, encoding="utf-8") as f:
        return render_template_string(f.read(), **context)

app = Flask(__name__)

# ---------- Hardcoded config (edit these directly — no environment variables needed) ----------
SECRET_KEY_VALUE = "a0ba020bdf927145294924f26353b7ee6b882c1e8660ae5299b043422aadf49e"
ADMIN_PASSWORD_VALUE = "tillu0010"          # <-- change this to your own password
TELEGRAM_BOT_TOKEN_VALUE = "8444571118:AAGFkyx4Ez_H4QUuYCOhOtynJKop_YJEVPY"
TELEGRAM_CHAT_ID_VALUE = "8488473179"
# ------------------------------------------------------------------------------------------

app.secret_key = os.environ.get("SECRET_KEY") or SECRET_KEY_VALUE
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12  # 12 hours

LOG_LINES_KEPT = 400

# ---------- Telegram (OTP delivery + crash alerts) ----------

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") or TELEGRAM_BOT_TOKEN_VALUE
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID") or TELEGRAM_CHAT_ID_VALUE
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def send_telegram(text, html=False):
    """Best-effort — a Telegram outage should never break login or the dashboard."""
    if not TELEGRAM_ENABLED:
        return False
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    if html:
        payload["parse_mode"] = "HTML"
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data=payload,
            timeout=10,
        )
        return True
    except Exception:
        return False


def send_otp_telegram(code, is_resend=False):
    """<code> makes the number monospaced and tap-to-copy in Telegram."""
    label = "New API Manager login code" if is_resend else "API Manager login code"
    text = f"🔐 <b>{label}</b>\n\n<code>{code}</code>\n\nExpires in 5 minutes. Tap the code to copy it."
    send_telegram(text, html=True)


def notify_crash(name, reason):
    with lock:
        info = registry.get(name)
        tail = "\n".join(list(info["logs"])[-6:]) if info else ""
    send_telegram(f"🚨 API crashed: {name}\nReason: {reason}\n\nRecent output:\n{tail}"[:3800])


# ---------- Admin auth: password + 4-attempt lockout + Telegram OTP ----------

ADMIN_PASSWORD_PLAIN = os.environ.get("ADMIN_PASSWORD") or ADMIN_PASSWORD_VALUE
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD_PLAIN)

if TELEGRAM_ENABLED:
    print("Telegram OTP + crash alerts: ENABLED")
else:
    print("Telegram OTP + crash alerts: disabled (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable)")

LOGIN_MAX_ATTEMPTS = 4
LOGIN_LOCKOUT_SECONDS = 15 * 60
OTP_TTL_SECONDS = 5 * 60
OTP_MAX_ATTEMPTS = 5

login_state = {"fails": 0, "locked_until": 0}
otp_state = {"code": None, "expires": 0, "attempts": 0}
auth_lock = threading.Lock()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    now = time.time()
    error = None
    with auth_lock:
        locked_remaining = login_state["locked_until"] - now

    if locked_remaining > 0:
        m, s = divmod(int(locked_remaining), 60)
        return render_page("login.html", error=f"Too many failed attempts. Try again in {m}m {s}s.", locked=True, telegram_enabled=TELEGRAM_ENABLED)

    if request.method == "POST":
        pw = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, pw):
            with auth_lock:
                login_state["fails"] = 0
            session.permanent = True
            session["admin"] = True
            return redirect(url_for("index"))
        else:
            with auth_lock:
                login_state["fails"] += 1
                remaining = LOGIN_MAX_ATTEMPTS - login_state["fails"]
                if login_state["fails"] >= LOGIN_MAX_ATTEMPTS:
                    login_state["locked_until"] = time.time() + LOGIN_LOCKOUT_SECONDS
                    login_state["fails"] = 0
                    error = "Too many failed attempts. Locked for 15 minutes."
                else:
                    error = f"Incorrect password. {remaining} attempt(s) left."
    return render_page("login.html", error=error, telegram_enabled=TELEGRAM_ENABLED)


@app.route("/request-otp", methods=["POST"])
def request_otp():
    """Alternative to the password: get a one-time code on Telegram instead."""
    if not TELEGRAM_ENABLED:
        return redirect(url_for("login"))
    now = time.time()
    with auth_lock:
        locked_remaining = login_state["locked_until"] - now
    if locked_remaining > 0:
        return redirect(url_for("login"))
    code = f"{secrets.randbelow(1000000):06d}"
    with auth_lock:
        otp_state.update({"code": code, "expires": now + OTP_TTL_SECONDS, "attempts": 0})
    send_otp_telegram(code)
    session["awaiting_otp"] = True
    return redirect(url_for("verify_otp"))


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("awaiting_otp"):
        return redirect(url_for("login"))

    error = None
    now = time.time()

    if request.method == "POST":
        if request.form.get("resend"):
            with auth_lock:
                code = f"{secrets.randbelow(1000000):06d}"
                otp_state.update({"code": code, "expires": now + OTP_TTL_SECONDS, "attempts": 0})
            send_otp_telegram(code, is_resend=True)
            error = "A new code was sent."
        else:
            entered = request.form.get("otp", "").strip()
            with auth_lock:
                expired = now > otp_state["expires"]
                too_many = otp_state["attempts"] >= OTP_MAX_ATTEMPTS
                if not expired and not too_many and entered and entered == otp_state["code"]:
                    session.permanent = True
                    session["admin"] = True
                    session.pop("awaiting_otp", None)
                    otp_state.update({"code": None, "attempts": 0})
                    return redirect(url_for("index"))
                if expired:
                    error = "Code expired — request a new one."
                elif too_many:
                    error = "Too many attempts — request a new code."
                else:
                    otp_state["attempts"] += 1
                    error = "Incorrect code."
    return render_page("verify_otp.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- App registry ----------

# name -> {
#   "dir": folder, "entry": "main.py", "port": int|None,
#   "process": Popen|None, "status": str,
#     status in: stopped | installing | starting | running | crashed
#   "uploaded_at": float, "started_at": float|None,
#   "logs": deque[str],
#   "protected": bool, "password_hash": str|None,
# }
registry = {}
lock = threading.Lock()


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def app_dir_of(name):
    return os.path.join(APPS_DIR, name)


def list_files(info):
    """Every file (any type, recursively) inside an API's folder — config, templates, data, etc. all show up."""
    d = info["dir"]
    out = []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, d)
            out.append({"name": rel, "size": os.path.getsize(full), "is_py": fname.endswith(".py")})
    return sorted(out, key=lambda x: x["name"])


def dir_size_bytes(path):
    """Total size of an API folder on disk (storage usage)."""
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except OSError:
        pass
    return total


def compute_rps(info, window_sec=60):
    """Approximate requests-per-second over the last `window_sec` seconds."""
    times = info.get("request_times") or []
    if not times:
        return 0.0
    now = time.time()
    cutoff = now - window_sec
    recent = [t for t in times if t >= cutoff]
    if not recent:
        return 0.0
    return round(len(recent) / window_sec, 2)


def load_existing_apps():
    """Pick up any API folders already on disk (e.g. after a restart)."""
    if not os.path.isdir(APPS_DIR):
        return
    for name in sorted(os.listdir(APPS_DIR)):
        d = app_dir_of(name)
        if not os.path.isdir(d):
            continue
        py_files = []
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            for f in files:
                if f.endswith(".py"):
                    py_files.append(os.path.relpath(os.path.join(root, f), d))
        if not py_files:
            continue
        entry = "main.py" if "main.py" in py_files else ("app.py" if "app.py" in py_files else sorted(py_files)[0])
        registry[name] = {
            "dir": d,
            "entry": entry,
            "port": None,
            "process": None,
            "status": "stopped",
            "uploaded_at": os.path.getmtime(d),
            "started_at": None,
            "logs": collections.deque(maxlen=LOG_LINES_KEPT),
            "protected": False,
            "password_hash": None,
            "total_requests": 0,
            "success_count": 0,
            "error_count": 0,
            "total_latency_ms": 0.0,
            "request_times": collections.deque(maxlen=300),
            "last_request_at": None,
        }


load_existing_apps()


def log_line(info, text):
    for ln in (text.splitlines() or [text]):
        info["logs"].append(ln)


def _pump_logs(name, proc):
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            with lock:
                info = registry.get(name)
                if info is None:
                    break
                info["logs"].append(line)
    except Exception:
        pass


def _watch_running(name, proc):
    """Detects a crash that happens *after* the app was already running (not a manual stop)."""
    proc.wait()
    with lock:
        info = registry.get(name)
        if not info or info.get("process") is not proc:
            return  # already stopped/restarted intentionally — nothing to report
        info["status"] = "crashed"
        log_line(info, "[deployer] process exited unexpectedly")
    notify_crash(name, "process exited unexpectedly while running")


# ---------- Dashboard ----------

@app.route("/")
@login_required
def index():
    return render_page("index.html", telegram_enabled=TELEGRAM_ENABLED)


# ---------- List / status ----------

@app.route("/api/list")
@login_required
def api_list():
    now = time.time()
    with lock:
        data = []
        for name, info in sorted(registry.items()):
            uptime = (now - info["started_at"]) if info["started_at"] and info["status"] == "running" else None
            total_req = info.get("total_requests", 0)
            avg_latency = round(info["total_latency_ms"] / total_req, 1) if total_req else 0
            rps = compute_rps(info)
            storage_bytes = dir_size_bytes(info["dir"])
            data.append({
                "name": name,
                "status": info["status"],
                "entry": info["entry"],
                "url": f"/app/{name}/" if info["status"] in ("running", "starting") else None,
                "uploaded_at": info["uploaded_at"],
                "uptime": uptime,
                "files": list_files(info),
                "has_requirements": os.path.exists(os.path.join(info["dir"], "requirements.txt")),
                "protected": info.get("protected", False),
                # Traffic & storage metrics
                "total_requests": total_req,
                "success_count": info.get("success_count", 0),
                "error_count": info.get("error_count", 0),
                "rps": rps,
                "avg_latency_ms": avg_latency,
                "storage_bytes": storage_bytes,
                "last_request_at": info.get("last_request_at"),
            })
    return jsonify(data)


@app.route("/api/logs/<name>")
@login_required
def logs(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        return jsonify({"name": name, "status": info["status"], "logs": list(info["logs"])})


@app.route("/api/requirements/<name>")
@login_required
def get_requirements(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        path = os.path.join(info["dir"], "requirements.txt")
    content = ""
    if os.path.exists(path):
        with open(path) as f:
            content = f.read()
    return jsonify({"content": content})


# ---------- Access password per API ----------

@app.route("/api/password/<name>", methods=["POST"])
@login_required
def set_password(name):
    data = request.get_json(silent=True) or {}
    protected = bool(data.get("protected"))
    pw = (data.get("password") or "").strip()
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        if not protected:
            info["protected"] = False
            info["password_hash"] = None
        else:
            if pw:
                info["password_hash"] = generate_password_hash(pw)
            if not info["password_hash"]:
                return jsonify({"error": "set a password first"}), 400
            info["protected"] = True
    return jsonify({"name": name, "protected": info["protected"]})


# ---------- Create / upload ----------

def unique_name(safe):
    name = safe
    i = 1
    while name in registry:
        name = f"{safe}_{i}"
        i += 1
    return name


def safe_name_from(filename):
    raw = os.path.splitext(os.path.basename(filename))[0]
    return "".join(c for c in raw if c.isalnum() or c in "-_") or f"api{int(time.time())}"


def new_registry_entry(d, entry):
    return {
        "dir": d,
        "entry": entry,
        "port": None,
        "process": None,
        "status": "stopped",
        "uploaded_at": time.time(),
        "started_at": None,
        "logs": collections.deque(maxlen=LOG_LINES_KEPT),
        "protected": False,
        "password_hash": None,
        # Traffic & metrics
        "total_requests": 0,
        "success_count": 0,
        "error_count": 0,
        "total_latency_ms": 0.0,
        "request_times": collections.deque(maxlen=300),  # recent timestamps for RPS
        "last_request_at": None,
    }


@app.route("/api/upload", methods=["POST"])
@login_required
def upload_new():
    """Create a brand new API from a single entry .py file."""
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".py"):
        return jsonify({"error": "Please upload a .py file"}), 400

    safe = safe_name_from(file.filename)
    with lock:
        name = unique_name(safe)
        d = app_dir_of(name)
        os.makedirs(d, exist_ok=True)
        entry_filename = os.path.basename(file.filename)
        file.save(os.path.join(d, entry_filename))
        registry[name] = new_registry_entry(d, entry_filename)
    return jsonify({"name": name})


@app.route("/api/upload/zip", methods=["POST"])
@login_required
def upload_zip():
    """Create a new API from an uploaded .zip project (folder-style upload)."""
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".zip"):
        return jsonify({"error": "Please upload a .zip file"}), 400

    safe = safe_name_from(file.filename)
    with lock:
        name = unique_name(safe)
        d = app_dir_of(name)
    os.makedirs(d, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        zpath = os.path.join(tmp, "upload.zip")
        file.save(zpath)
        try:
            with zipfile.ZipFile(zpath) as zf:
                for member in zf.namelist():
                    norm = os.path.normpath(member)
                    if norm.startswith("..") or os.path.isabs(norm):
                        continue  # guard against zip-slip
                    zf.extract(member, d)
        except zipfile.BadZipFile:
            shutil.rmtree(d, ignore_errors=True)
            return jsonify({"error": "invalid zip file"}), 400

    # flatten a single wrapping top-level folder, e.g. myproject/main.py -> main.py
    entries = [e for e in os.listdir(d) if e != "__MACOSX"]
    if len(entries) == 1 and os.path.isdir(os.path.join(d, entries[0])):
        inner = os.path.join(d, entries[0])
        for f in os.listdir(inner):
            shutil.move(os.path.join(inner, f), os.path.join(d, f))
        os.rmdir(inner)
    macosx = os.path.join(d, "__MACOSX")
    if os.path.isdir(macosx):
        shutil.rmtree(macosx, ignore_errors=True)

    py_files = []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.relpath(os.path.join(root, f), d))

    if not py_files:
        shutil.rmtree(d, ignore_errors=True)
        return jsonify({"error": "zip contains no .py files"}), 400

    if "app.py" in py_files:
        entry = "app.py"
    elif "main.py" in py_files:
        entry = "main.py"
    else:
        entry = sorted(py_files)[0]

    with lock:
        registry[name] = new_registry_entry(d, entry)

    return jsonify({"name": name, "entry": entry, "files": len(py_files)})


@app.route("/api/upload/<name>/file", methods=["POST"])
@login_required
def upload_extra_file(name):
    """Add any support file (config, template, data, .py module — any type) to an API's folder.
    Pass 'relpath' to preserve a folder structure (e.g. 'templates/index.html')."""
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        target_dir = info["dir"]

    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "no file provided"}), 400

    # relpath lets a folder upload preserve its structure; falls back to a flat filename
    relpath = request.form.get("relpath") or file.filename
    norm = os.path.normpath(relpath).replace("\\", "/")
    if norm.startswith("..") or os.path.isabs(norm):
        return jsonify({"error": "invalid path"}), 400

    dest = os.path.join(target_dir, norm)
    os.makedirs(os.path.dirname(dest) or target_dir, exist_ok=True)
    file.save(dest)
    return jsonify({"name": name, "file": norm})


@app.route("/api/entry/<name>", methods=["POST"])
@login_required
def set_entry(name):
    """Change which .py file is actually run — useful when a project has several (e.g. main.py, app1.py, app2.py)."""
    data = request.get_json(silent=True) or {}
    entry = (data.get("entry") or "").strip()
    if not entry.endswith(".py"):
        return jsonify({"error": "entry point must be a .py file"}), 400

    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        target_dir = info["dir"]
        norm = os.path.normpath(entry).replace("\\", "/")
        if norm.startswith("..") or os.path.isabs(norm) or not os.path.isfile(os.path.join(target_dir, norm)):
            return jsonify({"error": "that file doesn't exist in this API's folder"}), 400
        info["entry"] = norm
    return jsonify({"name": name, "entry": norm})


@app.route("/api/requirements/<name>", methods=["POST"])
@login_required
def save_requirements(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        target_dir = info["dir"]
    content = (request.get_json(silent=True) or {}).get("content", "")
    path = os.path.join(target_dir, "requirements.txt")
    if content.strip():
        with open(path, "w") as f:
            f.write(content.strip() + "\n")
    elif os.path.exists(path):
        os.remove(path)
    return jsonify({"name": name})


@app.route("/api/file/<name>/<path:filename>", methods=["DELETE"])
@login_required
def delete_file(name, filename):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        if filename == info["entry"]:
            return jsonify({"error": "can't delete the entry file — delete the whole API instead"}), 400
        target_dir = info["dir"]

    norm = os.path.normpath(filename)
    if norm.startswith("..") or os.path.isabs(norm):
        return jsonify({"error": "invalid path"}), 400
    path = os.path.join(target_dir, norm)
    try:
        os.remove(path)
    except OSError:
        pass
    return jsonify({"name": name, "file": filename})


# ---------- Start / stop / restart / delete ----------

def _boot_sequence(name):
    """Runs in a background thread: install deps if present, then launch the process."""
    with lock:
        info = registry.get(name)
        if not info:
            return
        req_path = os.path.join(info["dir"], "requirements.txt")
        has_req = os.path.exists(req_path)
        info["logs"].clear()
        info["status"] = "installing" if has_req else "starting"
        target_dir = info["dir"]
        entry = info["entry"]

    if has_req:
        log_line(info, "[installer] installing requirements.txt ...")
        try:
            result = subprocess.run(
                ["pip", "install", "--break-system-packages", "-r", "requirements.txt"],
                cwd=target_dir, capture_output=True, text=True, timeout=180,
            )
            with lock:
                info = registry.get(name)
                if not info:
                    return
                log_line(info, result.stdout)
                if result.returncode != 0:
                    log_line(info, result.stderr)
                    log_line(info, "[installer] failed — see output above")
                    info["status"] = "crashed"
                    should_notify = True
                else:
                    log_line(info, "[installer] done")
                    info["status"] = "starting"
                    should_notify = False
            if should_notify:
                notify_crash(name, "dependency install failed")
                return
        except Exception as e:
            with lock:
                info = registry.get(name)
                if info:
                    log_line(info, f"[installer] error: {e}")
                    info["status"] = "crashed"
            notify_crash(name, f"installer error: {e}")
            return

    port = find_free_port()
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["HOST"] = "127.0.0.1"

    with lock:
        info = registry.get(name)
        if not info:
            return
        log_line(info, f"[deployer] starting {entry} on port {port} ...")
        try:
            proc = subprocess.Popen(
                ["python3", entry],
                env=env, cwd=target_dir,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        except Exception as e:
            log_line(info, f"[deployer] failed to launch: {e}")
            info["status"] = "crashed"
            notify_crash(name, f"failed to launch: {e}")
            return
        info["process"] = proc
        info["port"] = port
        info["started_at"] = time.time()

    threading.Thread(target=_pump_logs, args=(name, proc), daemon=True).start()

    time.sleep(1.5)
    with lock:
        info = registry.get(name)
        if not info:
            return
        if info["process"] and info["process"].poll() is None:
            info["status"] = "running"
            log_line(info, "[deployer] running")
            alive = True
        else:
            info["status"] = "crashed"
            log_line(info, "[deployer] process exited — check output above")
            alive = False

    if alive:
        threading.Thread(target=_watch_running, args=(name, proc), daemon=True).start()
    else:
        notify_crash(name, "process exited immediately after starting")


@app.route("/api/start/<name>", methods=["POST"])
@login_required
def start(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        if info["status"] in ("running", "starting", "installing"):
            return jsonify({"error": "already running"}), 400
    threading.Thread(target=_boot_sequence, args=(name,), daemon=True).start()
    return jsonify({"name": name, "url": f"/app/{name}/"})


def _kill_locked(info):
    proc = info.get("process")
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@app.route("/api/stop/<name>", methods=["POST"])
@login_required
def stop(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        _kill_locked(info)
        info["process"] = None
        info["port"] = None
        info["status"] = "stopped"
        info["started_at"] = None
        log_line(info, "[deployer] stopped")
    return jsonify({"name": name})


@app.route("/api/restart/<name>", methods=["POST"])
@login_required
def restart(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        _kill_locked(info)
        info["process"] = None
        info["port"] = None
        info["status"] = "stopped"
        info["started_at"] = None
    threading.Thread(target=_boot_sequence, args=(name,), daemon=True).start()
    return jsonify({"name": name, "url": f"/app/{name}/"})


@app.route("/api/delete/<name>", methods=["POST"])
@login_required
def delete(name):
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        _kill_locked(info)
        target_dir = info["dir"]
        del registry[name]
    try:
        shutil.rmtree(target_dir)
    except OSError:
        pass
    return jsonify({"name": name})


# ---------- Reverse proxy so each API gets a stable public URL ----------

@app.route("/app/<name>/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/app/<name>/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(name, subpath):
    with lock:
        info = registry.get(name)
    if not info or info["status"] not in ("running", "starting"):
        return jsonify({"error": "This API is not running"}), 502

    if info.get("protected"):
        supplied = request.args.get("pass") or request.headers.get("X-Api-Pass", "")
        if not supplied or not info.get("password_hash") or not check_password_hash(info["password_hash"], supplied):
            return jsonify({"error": "password required — add ?pass=yourpassword to the URL"}), 401

    port = info["port"]
    url = f"http://127.0.0.1:{port}/{subpath}"
    start = time.time()
    status_code = 502
    try:
        upstream = requests.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=request.get_data(),
            params={k: v for k, v in request.args.items() if k != "pass"},
            timeout=15,
        )
        status_code = upstream.status_code
        latency_ms = (time.time() - start) * 1000

        # Record traffic metrics + print request to the API's live log
        with lock:
            info = registry.get(name)
            if info:
                info["total_requests"] = info.get("total_requests", 0) + 1
                info["total_latency_ms"] = info.get("total_latency_ms", 0.0) + latency_ms
                info["request_times"].append(time.time())
                info["last_request_at"] = time.time()
                if status_code >= 400:
                    info["error_count"] = info.get("error_count", 0) + 1
                else:
                    info["success_count"] = info.get("success_count", 0) + 1
                # Print request into the API's output log so you can see it live
                method = request.method
                path = "/" + (subpath or "")
                client = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
                log_line(info, f"[req] {method} {path} → {status_code}  {latency_ms:.0f}ms  from {client}")

        excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        headers = [(k, v) for k, v in upstream.raw.headers.items() if k.lower() not in excluded]
        return Response(upstream.content, status_code, headers)

    except requests.exceptions.RequestException as e:
        latency_ms = (time.time() - start) * 1000
        with lock:
            info = registry.get(name)
            if info:
                info["total_requests"] = info.get("total_requests", 0) + 1
                info["error_count"] = info.get("error_count", 0) + 1
                info["total_latency_ms"] = info.get("total_latency_ms", 0.0) + latency_ms
                info["request_times"].append(time.time())
                info["last_request_at"] = time.time()
                log_line(info, f"[req] {request.method} /{subpath or ''} → ERROR  {latency_ms:.0f}ms  ({e})")
        return jsonify({"error": f"upstream error: {e}"}), 502


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
