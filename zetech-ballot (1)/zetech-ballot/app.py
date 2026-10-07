"""
Zetech Electronic Ballot System
Flask + SQLite.  Run:  python app.py   then open http://127.0.0.1:5000
"""
import csv
import hmac
import hashlib
import io
import os
import secrets
import smtplib
import sqlite3
import time
import uuid
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, send_from_directory, session)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "ballot.db"))
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(BASE, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

PHOTO_EXT = {"png", "jpg", "jpeg", "webp"}
RESULTS_EXT = {"pdf", "png", "jpg", "jpeg"}


def load_secret():
    """Use SECRET_KEY if set, otherwise create one once and keep it in a file."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    return open(path).read().strip()


app = Flask(__name__)
app.secret_key = load_secret()
app.config.update(
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,           # 8 MB per request
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),  # expires after inactivity
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute("PRAGMA journal_mode = WAL")
    has = c.execute("SELECT name FROM sqlite_master WHERE name='students'").fetchone()
    if not has:
        with open(os.path.join(BASE, "schema.sql"), encoding="utf-8") as f:
            c.executescript(f.read())
    c.execute("""CREATE TABLE IF NOT EXISTS login_codes (
        student_id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL, expires_at REAL NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, sent_at REAL NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students(student_id))""")
    if not c.execute("SELECT 1 FROM admins").fetchone():
        c.execute(
            "INSERT INTO admins (full_name, phone_number, department, registration_no, password)"
            " VALUES (?,?,?,?,?)",
            ("Kariuki Susan", "0748672922", "ICT", "456",
             generate_password_hash(os.environ.get("ADMIN_PASSWORD", "456"))))
    c.commit()
    c.close()


def current_election():
    return db().execute("SELECT * FROM elections ORDER BY election_id DESC LIMIT 1").fetchone()


def log(action, details="", actor_id=None, role=None):
    db().execute(
        "INSERT INTO audit_log (actor_id, actor_role, action, details) VALUES (?,?,?,?)",
        (actor_id if actor_id is not None else session.get("uid"),
         role or session.get("role"), action, details))


# ---------------------------------------------------------------- security
FAILS = {}


def is_locked(key):
    n, until = FAILS.get(key, (0, 0))
    if until and until <= time.time():
        FAILS.pop(key, None)
        return False
    return until > time.time()


def register_fail(key):
    n, _ = FAILS.get(key, (0, 0))
    n += 1
    FAILS[key] = (n, time.time() + 300 if n >= 5 else 0)


def need(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if not session.get("uid"):
                flash("Please log in to continue (sessions end after 15 minutes of inactivity).", "err")
                return redirect("/login")
            if roles and session.get("role") not in roles:
                return redirect("/")
            session.permanent = True
            return f(*a, **k)
        return wrapper
    return deco


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent, real = request.form.get("csrf", ""), session.get("csrf", "")
        if not real or not secrets.compare_digest(sent, real):
            abort(400, "Your form expired. Go back, refresh the page and try again.")


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return dict(csrf=session["csrf"], role=session.get("role"),
                user_name=session.get("name"), election=current_election())


@app.template_filter("eat")
def eat(ts):
    """SQLite stores UTC; show East Africa Time (UTC+3)."""
    if not ts:
        return "-"
    try:
        dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S") + timedelta(hours=3)
        return dt.strftime("%d %b %Y, %H:%M")
    except ValueError:
        return ts


@app.template_filter("initials")
def initials(name):
    parts = (name or "?").split()
    return (parts[0][0] + (parts[-1][0] if len(parts) > 1 else "")).upper()


@app.errorhandler(400)
def bad(e):
    flash(getattr(e, "description", "Bad request."), "err")
    return redirect(request.referrer or "/login")


@app.errorhandler(413)
def too_big(e):
    flash("That upload is too large. Keep files under 8 MB in total.", "err")
    return redirect(request.referrer or "/")


# ---------------------------------------------------------------- uploads
def save_upload(file, prefix, allowed):
    """Save an uploaded file with a random name. Returns (filename|None, error|None)."""
    if not file or not file.filename:
        return None, None
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed:
        return None, "Allowed file types: " + ", ".join(sorted(allowed)) + "."
    name = f"{prefix}_{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_DIR, name))
    return name, None


def remove_upload(name):
    if name:
        try:
            os.remove(os.path.join(UPLOAD_DIR, os.path.basename(name)))
        except OSError:
            pass


@app.route("/uploads/<path:fn>")
@need()
def uploads(fn):
    fn = os.path.basename(fn)
    if fn.startswith("photo_"):
        pass
    elif fn.startswith("results_"):
        if session["role"] != "admin":
            own = db().execute("SELECT 1 FROM candidates WHERE results_path=? AND student_id=?",
                               (fn, session["uid"])).fetchone()
            if not own:
                abort(403)
    else:
        abort(404)
    return send_from_directory(UPLOAD_DIR, fn)


# ---------------------------------------------------------------- auth
@app.route("/")
def index():
    if session.get("uid"):
        return redirect("/admin" if session.get("role") == "admin" else "/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        which = request.form.get("role", "student")
        ident = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        key = f"{which}:{ident.lower()}"
        if is_locked(key):
            flash("Too many wrong attempts. Wait 5 minutes and try again.", "err")
            return render_template("login.html", which=which)
        if which == "admin":
            u = db().execute("SELECT * FROM admins WHERE registration_no=?", (ident,)).fetchone()
            if u and check_password_hash(u["password"], pw):
                FAILS.pop(key, None)
                session.clear()
                session.update(uid=u["admin_id"], role="admin", name=u["full_name"])
                session.permanent = True
                log("Admin logged in")
                db().commit()
                return redirect("/admin")
        else:
            s = db().execute("SELECT * FROM students WHERE UPPER(admission_number)=UPPER(?)",
                             (ident,)).fetchone()
            if s and s["password"] is None:
                flash("Your account isn't activated yet. Set a password below to start.", "ok")
                return redirect("/activate?adm=" + ident)
            if s and check_password_hash(s["password"], pw):
                FAILS.pop(key, None)
                session.clear()
                session["pending"] = s["student_id"]   # password OK, email code still needed
                session.permanent = True
                status, msg = issue_code(s)
                flash(msg, "err" if status == "fail" else "ok")
                return redirect("/verify")
        register_fail(key)
        flash("Those details don't match. Check your ID and password and try again.", "err")
        return render_template("login.html", which=which)
    return render_template("login.html", which=request.args.get("as", "student"))


# ---------------------------------------------------------------- email verification
CODE_TTL = 300        # code valid for 5 minutes
CODE_MAX_TRIES = 5
RESEND_WAIT = 30      # seconds between emails


def mask_email(e):
    name, _, dom = e.partition("@")
    return (name[:2] + "*" * max(len(name) - 2, 1)) + "@" + dom


def hash_code(code):
    return hmac.new(app.secret_key.encode(), code.encode(), hashlib.sha256).hexdigest()


def send_code_email(to, name, code):
    """Returns (status, message). status: sent | demo | fail."""
    host = os.environ.get("SMTP_HOST")
    if not host:  # no email server configured: demo mode (prints code in the terminal)
        print(f"[ZETECH BALLOT - DEMO MODE] verification code for {to}: {code}", flush=True)
        return "demo", f"Demo mode: no email server is set up yet, so your code is {code}."
    try:
        m = EmailMessage()
        m["Subject"] = "Your Zetech Ballot verification code"
        m["From"] = os.environ.get("SMTP_FROM") or os.environ["SMTP_USER"]
        m["To"] = to
        m.set_content(f"Hi {name.split()[0]},\n\nYour Zetech Ballot verification code is {code}.\n"
                      f"It expires in 5 minutes. If you did not try to log in, ignore this email "
                      f"and do not share the code with anyone.\n")
        port = int(os.environ.get("SMTP_PORT", 587))
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as srv:
                srv.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
                srv.send_message(m)
        else:
            with smtplib.SMTP(host, port, timeout=15) as srv:
                srv.starttls()
                srv.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
                srv.send_message(m)
        return "sent", f"We emailed a 6-digit code to {mask_email(to)}. It expires in 5 minutes."
    except Exception as exc:  # network / login problems
        print("[ZETECH BALLOT] email failed:", exc, flush=True)
        return "fail", "We couldn't send the email right now. Press 'Send a new code' to try again."


def issue_code(student):
    code = f"{secrets.randbelow(10 ** 6):06d}"
    now = time.time()
    db().execute("""INSERT INTO login_codes (student_id, code_hash, expires_at, attempts, sent_at)
                    VALUES (?,?,?,0,?) ON CONFLICT(student_id) DO UPDATE SET
                    code_hash=excluded.code_hash, expires_at=excluded.expires_at,
                    attempts=0, sent_at=excluded.sent_at""",
                 (student["student_id"], hash_code(code), now + CODE_TTL, now))
    db().commit()
    status, msg = send_code_email(student["email"], student["full_name"], code)
    log("Verification code sent" if status != "fail" else "Verification email failed",
        mask_email(student["email"]), student["student_id"], "student")
    db().commit()
    return status, msg


@app.route("/verify", methods=["GET", "POST"])
def verify():
    sid = session.get("pending")
    if not sid:
        return redirect("/login")
    d = db()
    s = d.execute("SELECT * FROM students WHERE student_id=?", (sid,)).fetchone()
    if not s:
        session.clear()
        return redirect("/login")
    if request.method == "POST":
        row = d.execute("SELECT * FROM login_codes WHERE student_id=?", (sid,)).fetchone()
        if request.form.get("step") == "resend":
            wait = RESEND_WAIT - (time.time() - row["sent_at"]) if row else 0
            if wait > 0:
                flash(f"Please wait {int(wait) + 1} seconds before asking for a new code.", "err")
            else:
                status, msg = issue_code(s)
                flash(msg, "err" if status == "fail" else "ok")
        else:
            code = "".join(ch for ch in request.form.get("code", "") if ch.isdigit())
            if not row or row["expires_at"] < time.time():
                flash("That code has expired. Send a new code.", "err")
            elif row["attempts"] >= CODE_MAX_TRIES:
                d.execute("DELETE FROM login_codes WHERE student_id=?", (sid,))
                log("Verification locked (too many wrong codes)", actor_id=sid, role="student")
                d.commit()
                session.clear()
                flash("Too many wrong codes. Log in again to get a new one.", "err")
                return redirect("/login")
            elif hmac.compare_digest(row["code_hash"], hash_code(code)):
                d.execute("DELETE FROM login_codes WHERE student_id=?", (sid,))
                session.clear()
                session.update(uid=s["student_id"], role="student", name=s["full_name"])
                session.permanent = True
                log("Student logged in (email verified)")
                d.commit()
                return redirect("/dashboard")
            else:
                d.execute("UPDATE login_codes SET attempts = attempts + 1 WHERE student_id=?", (sid,))
                d.commit()
                left = CODE_MAX_TRIES - row["attempts"] - 1
                flash(f"Wrong code. {left} {'try' if left == 1 else 'tries'} left.", "err")
    session.permanent = True
    return render_template("verify.html", email_hint=mask_email(s["email"]))


@app.route("/activate", methods=["GET", "POST"])
def activate():
    if request.method == "POST":
        adm = request.form.get("admission_number", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        s = db().execute("SELECT * FROM students WHERE UPPER(admission_number)=UPPER(?)", (adm,)).fetchone()
        if not s or s["email"].lower() != email:
            flash("We couldn't match that admission number and school email.", "err")
        elif s["password"] is not None:
            flash("This account is already activated. Log in instead.", "err")
            return redirect("/login")
        elif len(pw) < 6:
            flash("Choose a password with at least 6 characters.", "err")
        elif pw != pw2:
            flash("The two passwords don't match.", "err")
        else:
            db().execute("UPDATE students SET password=? WHERE student_id=?",
                         (generate_password_hash(pw), s["student_id"]))
            log("Account activated", s["admission_number"], s["student_id"], "student")
            db().commit()
            flash("Account activated! Log in with your admission number.", "ok")
            return redirect("/login")
    return render_template("activate.html", adm=request.args.get("adm", ""))


@app.route("/logout")
def logout():
    if session.get("uid"):
        log("Logged out")
        db().commit()
    session.clear()
    return redirect("/login")


# ---------------------------------------------------------------- results helpers
def tally(election_id):
    rows = db().execute("""
        SELECT p.position_id, p.position_name, c.candidate_id, s.full_name, c.photo_path,
               COUNT(v.vote_id) AS votes
        FROM positions p
        LEFT JOIN candidates c ON c.position_id = p.position_id AND c.status = 'approved'
        LEFT JOIN students s   ON s.student_id = c.student_id
        LEFT JOIN votes v      ON v.candidate_id = c.candidate_id AND v.election_id = ?
        GROUP BY p.position_id, c.candidate_id
        ORDER BY p.position_id, votes DESC, s.full_name""", (election_id,)).fetchall()
    out = {}
    for r in rows:
        p = out.setdefault(r["position_id"], dict(id=r["position_id"], name=r["position_name"],
                                                  total=0, candidates=[]))
        if r["candidate_id"]:
            p["candidates"].append(dict(id=r["candidate_id"], name=r["full_name"],
                                        photo=r["photo_path"], votes=r["votes"]))
            p["total"] += r["votes"]
    for p in out.values():
        for c in p["candidates"]:
            c["pct"] = round(100 * c["votes"] / p["total"]) if p["total"] else 0
    return list(out.values())


def turnout(election_id):
    total = db().execute("SELECT COUNT(*) FROM students").fetchone()[0]
    voted = db().execute("SELECT COUNT(DISTINCT student_id) FROM votes WHERE election_id=?",
                         (election_id,)).fetchone()[0]
    return dict(voters=voted, total=total, pct=round(100 * voted / total) if total else 0)


@app.route("/results")
@need()
def results_page():
    return render_template("results.html")


@app.route("/api/results")
@need()
def api_results():
    el = current_election()
    positions = tally(el["election_id"])
    return jsonify(election=dict(title=el["title"], status=el["status"]),
                   turnout=turnout(el["election_id"]),
                   total_votes=sum(p["total"] for p in positions),
                   positions=positions)


# ---------------------------------------------------------------- student pages
@app.route("/dashboard")
@need("student")
def dashboard():
    d, uid, el = db(), session["uid"], current_election()
    positions = d.execute("SELECT * FROM positions ORDER BY position_id").fetchall()
    mine = {r["position_id"]: r["full_name"] for r in d.execute(
        """SELECT v.position_id, s.full_name FROM votes v
           JOIN candidates c ON c.candidate_id = v.candidate_id
           JOIN students s ON s.student_id = c.student_id
           WHERE v.student_id=? AND v.election_id=?""", (uid, el["election_id"]))}
    app_row = d.execute(
        """SELECT c.*, p.position_name FROM candidates c JOIN positions p USING(position_id)
           WHERE c.student_id=? ORDER BY (c.status='rejected'), c.candidate_id DESC""", (uid,)).fetchone()
    n_cands = d.execute("SELECT COUNT(*) FROM candidates WHERE status='approved'").fetchone()[0]
    return render_template("dashboard.html", positions=positions, mine=mine, app_row=app_row,
                           n_cands=n_cands, t=turnout(el["election_id"]))


@app.route("/ballot")
@need("student")
def ballot():
    d, uid, el = db(), session["uid"], current_election()
    positions = d.execute("SELECT * FROM positions ORDER BY position_id").fetchall()
    cands = {}
    for c in d.execute("""SELECT c.*, s.full_name, s.admission_number FROM candidates c
                          JOIN students s ON s.student_id = c.student_id
                          WHERE c.status='approved' ORDER BY s.full_name"""):
        cands.setdefault(c["position_id"], []).append(c)
    mine = {r["position_id"]: r["candidate_id"] for r in d.execute(
        "SELECT position_id, candidate_id FROM votes WHERE student_id=? AND election_id=?",
        (uid, el["election_id"]))}
    return render_template("ballot.html", positions=positions, cands=cands, mine=mine)


@app.route("/vote", methods=["POST"])
@need("student")
def vote():
    d, uid, el = db(), session["uid"], current_election()
    try:
        cid = int(request.form.get("candidate_id", ""))
    except ValueError:
        flash("Pick a candidate first.", "err")
        return redirect("/ballot")
    c = d.execute("SELECT * FROM candidates WHERE candidate_id=? AND status='approved'", (cid,)).fetchone()
    if el["status"] != "open":
        flash("Voting isn't open right now.", "err")
    elif not c:
        flash("That candidate isn't on the ballot.", "err")
    else:
        try:  # UNIQUE(student_id, position_id, election_id) blocks double voting in the database
            d.execute("INSERT INTO votes (student_id, candidate_id, position_id, election_id) VALUES (?,?,?,?)",
                      (uid, c["candidate_id"], c["position_id"], el["election_id"]))
            pos = d.execute("SELECT position_name FROM positions WHERE position_id=?",
                            (c["position_id"],)).fetchone()[0]
            log("Vote cast", f"Position: {pos} (election #{el['election_id']})")
            d.commit()
            flash(f"Your vote for {pos} is recorded. Thank you!", "ok")
        except sqlite3.IntegrityError:
            d.rollback()
            flash("You already voted for this position.", "err")
    return redirect("/ballot")


@app.route("/apply", methods=["GET", "POST"])
@need("student")
def apply():
    d, uid, el = db(), session["uid"], current_election()
    positions = d.execute("SELECT * FROM positions ORDER BY position_id").fetchall()
    mine = d.execute(
        """SELECT c.*, p.position_name FROM candidates c JOIN positions p USING(position_id)
           WHERE c.student_id=? ORDER BY (c.status='rejected'), c.candidate_id DESC""", (uid,)).fetchone()

    if request.method == "POST":
        errors = []
        if el["status"] == "open":
            errors.append("Applications are closed while voting is open.")
        try:
            pid = int(request.form.get("position_id", ""))
            if not d.execute("SELECT 1 FROM positions WHERE position_id=?", (pid,)).fetchone():
                raise ValueError
        except ValueError:
            pid = None
            errors.append("Choose the position you are running for.")
        manifesto = request.form.get("manifesto", "").strip()
        if not 30 <= len(manifesto) <= 1500:
            errors.append("Your manifesto should be between 30 and 1500 characters.")
        if not request.form.get("fee"):
            errors.append("Confirm that your fees are cleared. The Dean's office will verify it.")

        same = None
        if pid:
            same = d.execute("SELECT * FROM candidates WHERE student_id=? AND position_id=?",
                             (uid, pid)).fetchone()
            other = d.execute("""SELECT COUNT(*) FROM candidates
                                 WHERE student_id=? AND position_id!=? AND status!='rejected'""",
                              (uid, pid)).fetchone()[0]
            if other:
                errors.append("You already have an active application for another position. One at a time.")
            if same and same["status"] == "approved":
                errors.append("Your application is approved, so it can't be edited now.")

        photo, e1 = save_upload(request.files.get("photo"), "photo", PHOTO_EXT)
        results, e2 = save_upload(request.files.get("results"), "results", RESULTS_EXT)
        errors += [e for e in (e1, e2) if e]
        if pid and not (same and same["photo_path"]) and not photo and not e1:
            errors.append("Upload a clear photo of yourself.")
        if pid and not (same and same["results_path"]) and not results and not e2:
            errors.append("Upload your academic results (PDF or image).")

        if errors:
            remove_upload(photo)
            remove_upload(results)
            for e in errors:
                flash(e, "err")
            return render_template("apply.html", positions=positions, mine=mine, form=request.form)

        if same:
            if photo:
                remove_upload(same["photo_path"])
            if results:
                remove_upload(same["results_path"])
            d.execute("""UPDATE candidates SET manifesto=?, photo_path=?, results_path=?, fee_compliance=1,
                         status='pending', applied_at=CURRENT_TIMESTAMP WHERE candidate_id=?""",
                      (manifesto, photo or same["photo_path"], results or same["results_path"],
                       same["candidate_id"]))
            log("Candidate application updated")
        else:
            d.execute("""INSERT INTO candidates (student_id, position_id, manifesto, photo_path,
                         results_path, fee_compliance) VALUES (?,?,?,?,?,1)""",
                      (uid, pid, manifesto, photo, results))
            log("Candidate application submitted")
        d.commit()
        flash("Application saved. The Dean's office will review it soon.", "ok")
        return redirect("/apply")
    return render_template("apply.html", positions=positions, mine=mine, form=None)


# ---------------------------------------------------------------- admin
@app.route("/admin")
@need("admin")
def admin():
    d, el = db(), current_election()
    cands = d.execute("""SELECT c.*, s.full_name, s.admission_number, s.email, p.position_name
                         FROM candidates c JOIN students s ON s.student_id=c.student_id
                         JOIN positions p ON p.position_id=c.position_id
                         ORDER BY CASE c.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
                                  p.position_id, c.applied_at""").fetchall()
    voters = d.execute("""SELECT s.*, (SELECT COUNT(*) FROM votes v WHERE v.student_id=s.student_id
                                       AND v.election_id=?) AS n_votes
                          FROM students s ORDER BY s.admission_number""", (el["election_id"],)).fetchall()
    audit = d.execute("""SELECT a.*, COALESCE(s.full_name, ad.full_name) AS who FROM audit_log a
                         LEFT JOIN students s ON a.actor_role='student' AND s.student_id=a.actor_id
                         LEFT JOIN admins ad ON a.actor_role='admin' AND ad.admin_id=a.actor_id
                         ORDER BY a.log_id DESC LIMIT 80""").fetchall()
    stats = dict(
        voters=len(voters),
        activated=sum(1 for v in voters if v["password"]),
        pending=sum(1 for c in cands if c["status"] == "pending"),
        approved=sum(1 for c in cands if c["status"] == "approved"),
        votes=d.execute("SELECT COUNT(*) FROM votes WHERE election_id=?", (el["election_id"],)).fetchone()[0],
        t=turnout(el["election_id"]))
    return render_template("admin.html", cands=cands, voters=voters, audit=audit, stats=stats,
                           n_positions=d.execute("SELECT COUNT(*) FROM positions").fetchone()[0])


@app.route("/admin/election", methods=["POST"])
@need("admin")
def admin_election():
    d, el, action = db(), current_election(), request.form.get("action")
    if action == "open":
        if not d.execute("SELECT 1 FROM candidates WHERE status='approved'").fetchone():
            flash("Approve at least one candidate before opening the election.", "err")
            return redirect("/admin")
        d.execute("""UPDATE elections SET status='open', start_time=COALESCE(start_time, CURRENT_TIMESTAMP),
                     end_time=NULL WHERE election_id=?""", (el["election_id"],))
        log("Election opened", el["title"])
        flash("Election is open. Students can vote now.", "ok")
    elif action == "pause":
        d.execute("UPDATE elections SET status='paused' WHERE election_id=?", (el["election_id"],))
        log("Election paused", el["title"])
        flash("Election paused.", "ok")
    elif action == "close":
        d.execute("UPDATE elections SET status='closed', end_time=CURRENT_TIMESTAMP WHERE election_id=?",
                  (el["election_id"],))
        log("Election closed", el["title"])
        flash("Election closed. Final results are on the results page.", "ok")
    elif action == "new":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Give the new election a title.", "err")
        elif el["status"] == "open":
            flash("Close the current election first.", "err")
        else:
            d.execute("INSERT INTO elections (title, status) VALUES (?, 'closed')", (title,))
            log("New election created", title)
            flash("New election created. Votes start from zero.", "ok")
    d.commit()
    return redirect("/admin")


@app.route("/admin/candidate/<int:cid>/<decision>", methods=["POST"])
@need("admin")
def admin_candidate(cid, decision):
    d = db()
    c = d.execute("""SELECT c.*, s.full_name FROM candidates c JOIN students s USING(student_id)
                     WHERE candidate_id=?""", (cid,)).fetchone()
    if not c:
        abort(404)
    if decision == "fee":
        d.execute("UPDATE candidates SET fee_compliance=? WHERE candidate_id=?",
                  (0 if c["fee_compliance"] else 1, cid))
        log("Fee compliance toggled", c["full_name"])
    elif decision in ("approve", "reject"):
        if decision == "approve" and not c["fee_compliance"]:
            flash("Mark fee compliance as verified before approving.", "err")
            return redirect("/admin#candidates")
        d.execute("UPDATE candidates SET status=? WHERE candidate_id=?",
                  ("approved" if decision == "approve" else "rejected", cid))
        log(f"Candidate {decision}d", c["full_name"])
        flash(f"{c['full_name']} {decision}d.", "ok")
    d.commit()
    return redirect("/admin#candidates")


@app.route("/admin/student", methods=["POST"])
@need("admin")
def admin_student():
    f = request.form
    vals = [f.get(k, "").strip() for k in ("admission_number", "full_name", "email", "phone_number")]
    if not all(vals):
        flash("Fill in every student field.", "err")
    else:
        try:
            db().execute("INSERT INTO students (admission_number, full_name, email, phone_number)"
                         " VALUES (?,?,?,?)", vals)
            log("Student added", vals[0])
            db().commit()
            flash(f"{vals[1]} added to the voter list.", "ok")
        except sqlite3.IntegrityError:
            flash("That admission number or email already exists.", "err")
    return redirect("/admin#voters")


@app.route("/admin/student/<int:sid>/reset", methods=["POST"])
@need("admin")
def admin_reset(sid):
    s = db().execute("SELECT * FROM students WHERE student_id=?", (sid,)).fetchone()
    if not s:
        abort(404)
    db().execute("UPDATE students SET password=NULL WHERE student_id=?", (sid,))
    log("Student password reset", s["admission_number"])
    db().commit()
    flash(f"{s['full_name']} can activate a new password now.", "ok")
    return redirect("/admin#voters")


@app.route("/admin/password", methods=["POST"])
@need("admin")
def admin_password():
    a = db().execute("SELECT * FROM admins WHERE admin_id=?", (session["uid"],)).fetchone()
    old, new = request.form.get("old", ""), request.form.get("new", "")
    if not check_password_hash(a["password"], old):
        flash("Your current password is wrong.", "err")
    elif len(new) < 6:
        flash("New password needs at least 6 characters.", "err")
    else:
        db().execute("UPDATE admins SET password=? WHERE admin_id=?",
                     (generate_password_hash(new), a["admin_id"]))
        log("Admin password changed")
        db().commit()
        flash("Password changed.", "ok")
    return redirect("/admin#settings")


@app.route("/admin/report.csv")
@need("admin")
def report():
    el = current_election()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([el["title"], "status: " + el["status"]])
    t = turnout(el["election_id"])
    w.writerow(["Turnout", f"{t['voters']} of {t['total']} students ({t['pct']}%)"])
    w.writerow([])
    w.writerow(["Position", "Candidate", "Votes", "Share %"])
    for p in tally(el["election_id"]):
        for c in p["candidates"]:
            w.writerow([p["name"], c["name"], c["votes"], c["pct"]])
    log("Report downloaded")
    db().commit()
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=election-report.csv"})


init_db()

if __name__ == "__main__":
    app.run(debug=True)
