"""
evilgenie multi-domain test web app (Flask + SQLite).

Two root domains, several subdomains each, all served by ONE Flask app on
127.0.0.1:5000. A local DNS server (dns_server.py) resolves them to 127.0.0.1.

    myapp.test
        www.myapp.test      -> landing / login start (email step)
        auth.myapp.test     -> password step, then OTP step
        api.myapp.test      -> JSON endpoints (verify-otp, session, profile)
        static.myapp.test   -> static assets (JS/CSS)
    cdn-corp.test
        cdn.cdn-corp.test   -> JS library CDN
        assets.cdn-corp.test-> images/assets
        media.cdn-corp.test -> (unused subdomain, for host-selection realism)

Login flow (spans both root domains):
    GET  www.myapp.test/            -> 302 -> www.myapp.test/login?next=/dashboard
    GET  www.myapp.test/login       -> email form (loads JS from cdn.cdn-corp.test,
                                       assets from assets.cdn-corp.test)
    POST www.myapp.test/login       -> 302 -> auth.myapp.test/password
    GET  auth.myapp.test/password   -> password form
    POST auth.myapp.test/password   -> 302 -> auth.myapp.test/otp
    GET  auth.myapp.test/otp        -> OTP page; JS fetch to api.myapp.test
    POST api.myapp.test/api/verify-otp (JSON) -> sets session cookie for .myapp.test,
                                       returns session_token in body
    GET  www.myapp.test/dashboard   -> final page; fetches api.myapp.test/api/session
                                       (Authorization: Bearer) and /api/profile

Demo credentials:  demo@example.com / Password123! / OTP 123456
"""

import os
import secrets
import socket
import sqlite3
import sys
import time

from flask import (Flask, g, jsonify, make_response, redirect, render_template,
                   request)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

app = Flask(__name__)

DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "Password123!"
DEMO_OTP = "123456"

# canonical hostnames
WWW = "www.myapp.test:5000"
AUTH = "auth.myapp.test:5000"
API = "api.myapp.test:5000"
STATIC = "static.myapp.test:5000"
CDN = "cdn.cdn-corp.test:5000"
ASSETS = "assets.cdn-corp.test:5000"


def url(host, path):
    return f"http://{host}{path}"


# ---------------------------------------------------------------- db helpers

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, otp TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS flows(
        id TEXT PRIMARY KEY, email TEXT, csrf TEXT, stage TEXT, created REAL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY, user_id INTEGER, created REAL)""")
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users(email, password, otp) VALUES(?,?,?)",
                    (DEMO_EMAIL, generate_password_hash(DEMO_PASSWORD), DEMO_OTP))
    con.commit()
    con.close()


def get_flow(flow_id):
    return get_db().execute("SELECT * FROM flows WHERE id=?",
                            (flow_id,)).fetchone()


def session_user(token):
    if not token:
        return None
    row = get_db().execute("SELECT user_id FROM sessions WHERE token=?",
                           (token,)).fetchone()
    return row["user_id"] if row else None


# ------------------------------------------------------------- host routing

@app.before_request
def route_by_host():
    """Dispatch to the right handler based on the Host header subdomain."""
    host = request.host.split(":")[0]
    path = request.path

    # static-ish subdomains serve files directly
    if host == "static.myapp.test" and path.startswith("/static/"):
        return None  # Flask's built-in static handler
    if host == "cdn.cdn-corp.test" and path.startswith("/cdn/"):
        return None
    if host == "assets.cdn-corp.test" and path.startswith("/assets/"):
        return None

    # everything else falls through to the route functions below
    return None


# ---------------------------------------------------------------- www (root 1)

@app.route("/")
def index():
    nxt = request.args.get("next", "/dashboard")
    return redirect(url(WWW, f"/login?next={nxt}"))


@app.route("/login", methods=["GET"])
def login_get():
    nxt = request.args.get("next", "/dashboard")
    flow_id = secrets.token_urlsafe(12)
    csrf = secrets.token_urlsafe(16)
    db = get_db()
    db.execute("INSERT INTO flows(id, email, csrf, stage, created) VALUES(?,?,?,?,?)",
               (flow_id, None, csrf, "email", time.time()))
    db.commit()
    resp = make_response(render_template(
        "login.html", next=nxt, flow_id=flow_id, csrf=csrf, error=None,
        cdn=CDN, assets=ASSETS, static=STATIC))
    resp.set_cookie("flow", flow_id, domain=".myapp.test")
    resp.set_cookie("tracker", secrets.token_hex(8), max_age=86400,
                    domain=".myapp.test")
    return resp


@app.route("/login", methods=["POST"])
def login_post():
    email = request.form.get("email", "").lower().strip()
    flow_id = request.form.get("flow_id", "")
    csrf = request.form.get("csrf_token", "")
    db = get_db()
    flow = get_flow(flow_id)
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not flow or flow["csrf"] != csrf or user is None:
        return render_template("login.html", next="/dashboard", flow_id=flow_id,
                               csrf=csrf, error="Invalid email or session.",
                               cdn=CDN, assets=ASSETS, static=STATIC), 200
    db.execute("UPDATE flows SET email=?, stage='password' WHERE id=?",
               (email, flow_id))
    db.commit()
    # cross to the auth subdomain (same root domain)
    return redirect(url(AUTH, "/password"))


# ---------------------------------------------------------------- auth (root 1)

@app.route("/password", methods=["GET"])
def password_get():
    flow = get_flow(request.cookies.get("flow", ""))
    if not flow or flow["stage"] != "password":
        return redirect(url(WWW, "/login"))
    csrf = secrets.token_urlsafe(16)
    get_db().execute("UPDATE flows SET csrf=? WHERE id=?", (csrf, flow["id"]))
    get_db().commit()
    return render_template("password.html", email=flow["email"],
                           flow_id=flow["id"], csrf=csrf, error=None,
                           cdn=CDN, assets=ASSETS)


@app.route("/password", methods=["POST"])
def password_post():
    flow_id = request.form.get("flow_id", "")
    password = request.form.get("password", "")
    csrf = request.form.get("csrf_token", "")
    db = get_db()
    flow = get_flow(flow_id)
    if not flow or flow["csrf"] != csrf or flow["stage"] != "password":
        return redirect(url(WWW, "/login"))
    user = db.execute("SELECT * FROM users WHERE email=?",
                      (flow["email"],)).fetchone()
    if user is None or not check_password_hash(user["password"], password):
        return render_template("password.html", email=flow["email"],
                               flow_id=flow_id, csrf=csrf,
                               error="Wrong password.", cdn=CDN, assets=ASSETS), 200
    db.execute("UPDATE flows SET stage='otp' WHERE id=?", (flow_id,))
    db.commit()
    return redirect(url(AUTH, "/otp"))


@app.route("/otp", methods=["GET"])
def otp_get():
    flow = get_flow(request.cookies.get("flow", ""))
    if not flow or flow["stage"] != "otp":
        return redirect(url(WWW, "/login"))
    csrf = secrets.token_urlsafe(16)
    get_db().execute("UPDATE flows SET csrf=? WHERE id=?", (csrf, flow["id"]))
    get_db().commit()
    return render_template("otp.html", flow_id=flow["id"], csrf=csrf,
                           otp=DEMO_OTP, api=API, cdn=CDN)


# ---------------------------------------------------------------- api (root 1)

@app.after_request
def add_cors(resp):
    """Permissive CORS for the demo so cross-subdomain fetch works."""
    origin = request.headers.get("Origin")
    if origin and ("myapp.test" in origin or "cdn-corp.test" in origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/api/verify-otp", methods=["OPTIONS"])
@app.route("/api/session", methods=["OPTIONS"])
@app.route("/api/profile", methods=["OPTIONS"])
def api_options():
    return "", 204


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json(silent=True) or {}
    flow = get_flow(data.get("flow_id", ""))
    if not flow or flow["csrf"] != data.get("csrf_token") or flow["stage"] != "otp":
        return jsonify({"status": "error", "message": "invalid flow"}), 403
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?",
                      (flow["email"],)).fetchone()
    if user is None or data.get("otp") != user["otp"]:
        return jsonify({"status": "error", "message": "wrong code"}), 200
    token = secrets.token_urlsafe(24)
    db.execute("INSERT INTO sessions(token, user_id, created) VALUES(?,?,?)",
               (token, user["id"], time.time()))
    db.execute("DELETE FROM flows WHERE id=?", (flow["id"],))
    db.commit()
    resp = make_response(jsonify({
        "status": "ok",
        "session_token": token,
        "redirect": url(WWW, "/dashboard"),
    }))
    resp.set_cookie("session_id", token, max_age=30 * 86400, domain=".myapp.test")
    resp.set_cookie("prefs", "theme=dark", max_age=365 * 86400, domain=".myapp.test")
    return resp


@app.route("/api/session")
def api_session():
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else None
    if not session_user(token):
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "display_name": "Demo User",
                    "token_type": "bearer"})


@app.route("/api/profile")
def api_profile():
    if not session_user(request.cookies.get("session_id")):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"email": DEMO_EMAIL, "plan": "pro",
                    "settings": {"theme": "dark", "notifications": True}})


# ---------------------------------------------------------------- dashboard

@app.route("/dashboard")
def dashboard():
    if not session_user(request.cookies.get("session_id")):
        return redirect(url(WWW, "/login"))
    return render_template("dashboard.html", api=API, cdn=CDN, assets=ASSETS)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url(WWW, "/")))
    resp.delete_cookie("session_id", domain=".myapp.test")
    return resp


# ---------------------------------------------------------------- cdn (root 2)

@app.route("/cdn/<path:filename>")
def cdn_serve(filename):
    if filename == "login.js":
        return app.send_static_file("login.js")
    if filename == "lib.js":
        return app.send_static_file("lib.js")
    return "not found", 404


@app.route("/assets/<path:filename>")
def assets_serve(filename):
    if filename == "logo.txt":
        return app.send_static_file("logo.txt")
    return "not found", 404


REQUIRED_HOSTS = [
    "myapp.test", "www.myapp.test", "auth.myapp.test", "api.myapp.test",
    "static.myapp.test",
    "cdn-corp.test", "cdn.cdn-corp.test", "assets.cdn-corp.test",
    "media.cdn-corp.test",
]


def _resolves(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def wait_for_hosts():
    """Print the required /etc/hosts entries and wait until they resolve."""
    missing = [h for h in REQUIRED_HOSTS if not _resolves(h)]
    if not missing:
        print("[+] All demo hostnames already resolve.")
        return
    print("\n" + "=" * 70)
    print("This demo uses two root domains and several subdomains.")
    print("Add the following line to /etc/hosts (e.g. sudo nano /etc/hosts):\n")
    print(f"127.0.0.1 {' '.join(REQUIRED_HOSTS)}")
    print("\n" + "=" * 70)
    while True:
        missing = [h for h in REQUIRED_HOSTS if not _resolves(h)]
        if not missing:
            print("[+] All demo hostnames resolve. Starting web app.")
            return
        print(f"[!] Still unresolved: {', '.join(missing)}")
        try:
            input("Press ENTER to re-check (Ctrl+C to quit)...")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(0)


if __name__ == "__main__":
    init_db()
    wait_for_hosts()
    app.run(host="127.0.0.1", port=5000, debug=False)
