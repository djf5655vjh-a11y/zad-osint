import os, re, time, secrets, shutil, tempfile, zipfile, datetime as dt
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, Response, g, send_file
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
import analyzer, db

db.init()
app = Flask(__name__)
app.secret_key = db.secret()
app.config.update(MAX_CONTENT_LENGTH=30 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("INSECURE_COOKIES") != "1")
ADMINS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAIL", "").split(",") if e.strip()}
UPI_ID, PRICE = os.environ.get("UPI_ID", "sunny8127@fam"), int(os.environ.get("PRICE", "99"))
TRIAL_SEC, MAX_BOTS = 24 * 3600, int(os.environ.get("MAX_BOTS_PER_USER", "5"))
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))

def bot_status(b):
    if b.get("suspended"): return "suspended"
    if not b.get("approved"): return "pending"
    if b.get("plan") == "permanent": return "permanent"
    return "trial" if (b.get("expires_at") or 0) > time.time() else "expired"
def entitled(b): return bot_status(b) in ("trial", "permanent")

@app.template_filter("ts")
def f_ts(t): return dt.datetime.fromtimestamp(t, IST).strftime("%d %b %Y, %I:%M %p") if t else "-"
@app.template_filter("left")
def f_left(b):
    if b.get("plan") == "permanent": return "Permanent"
    s = int((b.get("expires_at") or 0) - time.time())
    return "Expired" if s <= 0 else f"{s // 3600}h {s % 3600 // 60}m left"
@app.template_filter("badge")
def f_badge(s): return Markup(f'<span class="badge {s}">{s}</span>')
@app.template_filter("uptime")
def f_up(b):
    if b.get("state") != "running" or not b.get("started_at"): return "-"
    s = int(time.time() - b["started_at"]); return f"{s // 3600}h {s % 3600 // 60}m"

@app.before_request
def guard():
    g.user = None
    if session.get("uid"):
        u = db.get("users", session["uid"])
        if u and u.get("status") != "suspended": g.user = u
        else: session.clear()
    if request.method == "POST" and not secrets.compare_digest(request.form.get("_csrf", ""), session.get("csrf", "x")): abort(400)

@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16))
    ann = sorted(db.all("announcements"), key=lambda a: -a.get("ts", 0))[:3] if g.get("user") else []
    return {"user": g.get("user"), "csrf": session["csrf"], "price": PRICE, "upi": UPI_ID, "announcements": ann}

def login_required(f):
    @wraps(f)
    def w(*a, **k): return f(*a, **k) if g.user else redirect(url_for("login"))
    return w
def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if g.user.get("role") != "admin": abort(403)
        return f(*a, **k)
    return w
def alog(action): db.add("admin_logs", {"admin": g.user["email"], "action": action, "ts": time.time()})
def get_bot(bid, admin_ok=False):
    b = db.get("bots", bid)
    if not b or (b["uid"] != g.user["id"] and not (admin_ok and g.user.get("role") == "admin")): abort(404)
    return b

tries = {}
@app.route("/")
def index(): return redirect(url_for("dashboard") if g.user else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email, pw, name = request.form["email"].strip().lower(), request.form["password"], request.form["name"].strip()[:40]
        if not re.match(r"^[^@\s]+@[^@\s]+\.\w+$", email) or len(pw) < 6 or not name: flash("Name, valid email aur 6+ character password do.", "err")
        elif db.where("users", "email", email): flash("Ye email already registered hai.", "err")
        else:
            first = not db.all("users") and not ADMINS
            uid = db.add("users", {"email": email, "name": name, "pw": generate_password_hash(pw), "status": "active",
                                   "role": "admin" if email in ADMINS or first else "user", "created": time.time()})
            session["uid"] = uid; return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        recent = [t for t in tries.get(ip, []) if t > time.time() - 600]
        if len(recent) >= 10: flash("Bahut attempts. 10 minute baad try karo.", "err")
        else:
            m = db.where("users", "email", request.form["email"].strip().lower()); u = m[0] if m else None
            if u and check_password_hash(u["pw"], request.form["password"]):
                if u.get("status") == "suspended": flash("Account suspended hai.", "err")
                else: session.clear(); session["uid"] = u["id"]; return redirect(url_for("dashboard"))
            else: tries[ip] = recent + [time.time()]; flash("Email ya password galat hai.", "err")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    bots = sorted(db.where("bots", "uid", g.user["id"]), key=lambda b: -b["created"]); st = [bot_status(b) for b in bots]
    stats = {"total": len(bots), "running": sum(b.get("state") == "running" for b in bots), "stopped": sum(b.get("state") != "running" for b in bots),
             "expired": st.count("expired"), "permanent": st.count("permanent")}
    pays = sorted(db.where("payments", "uid", g.user["id"]), key=lambda p: -p["ts"])
    return render_template("dashboard.html", bots=bots, stats=stats, pays=pays[:5])

@app.route("/bots/new", methods=["GET", "POST"])
@login_required
def new_bot():
    templates = sorted([t for t in db.all("templates") if t.get("active")], key=lambda t: t["title"].lower())
    if request.method == "POST":
        if len(db.where("bots", "uid", g.user["id"])) >= MAX_BOTS: flash(f"Maximum {MAX_BOTS} bots allowed.", "err"); return redirect(url_for("dashboard"))
        bid, tid = db.new_id(), request.form.get("template_id")
        base = {"uid": g.user["id"], "owner": g.user["email"], "name": (request.form.get("name") or "My Bot").strip()[:40], "config": {},
                "configured": False, "suspended": False, "plan": "trial", "desired": "stopped", "state": "stopped", "created": time.time(), "restarts": 0}
        if tid:
            t = db.get("templates", tid)
            if not t: abort(404)
            base.update(source="template", template_id=tid, zip_path=t["zip_path"], own_zip=False, approved=True, expires_at=time.time() + TRIAL_SEC, **t["analysis"])
        else:
            f = request.files.get("zip")
            if not f or not f.filename.lower().endswith(".zip"): flash("ZIP file select karo.", "err"); return redirect(request.url)
            data = f.read()
            try: an = analyzer.analyze(data)
            except analyzer.BadZip as e: flash(str(e), "err"); return redirect(request.url)
            db.save_file(f"b_{bid}.zip", data)
            base.update(source="upload", zip_path=f"b_{bid}.zip", own_zip=True, size=len(data), approved=False, expires_at=None, **an)
        db.put("bots", bid, base)
        flash("Bot ban gaya. Ab configuration bharo." + ("" if base["approved"] else " Custom ZIP admin approval ke baad 24h trial pe chalega."), "ok")
        return redirect(url_for("bot_page", bid=bid))
    return render_template("new_bot.html", templates=templates, cats=sorted({t.get("category", "General") for t in templates}))

@app.route("/bots/<bid>")
@login_required
def bot_page(bid):
    b = get_bot(bid, True)
    return render_template("bot.html", b=b, status=bot_status(b), pays=sorted(db.where("payments", "bot_id", bid), key=lambda p: -p["ts"]))

@app.route("/bots/<bid>/config", methods=["POST"])
@login_required
def bot_config(bid):
    b = get_bot(bid); cfg, missing = dict(b.get("config") or {}), []
    for f in b.get("fields", []):
        v = request.form.get("f_" + f["key"], "").strip()
        if v: cfg[f["key"]] = v[:500]
        if f["required"] and not cfg.get(f["key"]): missing.append(f["label"])
    db.update("bots", bid, config=cfg, configured=not missing, restart_req=time.time() if b["state"] == "running" else b.get("restart_req", 0))
    flash("Saved." if not missing else "Saved, but required fields baaki hain: " + ", ".join(missing), "ok" if not missing else "err")
    return redirect(url_for("bot_page", bid=bid))

@app.route("/bots/<bid>/<action>", methods=["POST"])
@login_required
def bot_action(bid, action):
    b = get_bot(bid, True)
    if action in ("start", "restart"):
        if not entitled(b): flash("Bot active nahi hai (pending/expired/suspended).", "err")
        elif not b.get("configured"): flash("Pehle saari required configuration bharo.", "err")
        else: db.update("bots", bid, desired="running", restart_req=time.time() if action == "restart" else b.get("restart_req", 0), last_error=""); flash("Worker ko command bhej di.", "ok")
    elif action == "stop": db.update("bots", bid, desired="stopped"); flash("Stop command bhej di.", "ok")
    elif action == "delete":
        db.delete("bots", bid)
        if b.get("own_zip"): db.del_file(b["zip_path"])
        flash("Bot delete ho gaya.", "ok"); return redirect(url_for("dashboard"))
    return redirect(request.referrer or url_for("bot_page", bid=bid))

@app.route("/bots/<bid>/download")
@login_required
def bot_download(bid):
    b = get_bot(bid, True)
    if not b.get("own_zip"): abort(403)
    return Response(db.read_file(b["zip_path"]), mimetype="application/zip", headers={"Content-Disposition": f'attachment; filename="{re.sub(r"[^\w-]", "_", b["name"])}.zip"'})

@app.route("/api/bots/<bid>/status")
@login_required
def bot_api(bid):
    b = get_bot(bid, True)
    return jsonify(state=b.get("state"), status=bot_status(b), log=b.get("log_tail", ""), uptime=f_up(b), restarts=b.get("restarts", 0), error=b.get("last_error", ""))

@app.route("/bots/<bid>/pay", methods=["POST"])
@login_required
def bot_pay(bid):
    b = get_bot(bid); name, utr = request.form["name"].strip()[:60], re.sub(r"\s", "", request.form["utr"])
    if not name or not re.fullmatch(r"\d{12}", utr): flash("Name aur 12-digit UTR number dalo.", "err")
    elif not b.get("approved"): flash("Bot approve hone ke baad payment karo.", "err")
    elif db.where("payments", "utr", utr): flash("Ye UTR pehle hi submit ho chuka hai.", "err")
    else:
        db.add("payments", {"uid": g.user["id"], "email": g.user["email"], "bot_id": bid, "bot_name": b["name"], "name": name, "utr": utr, "amount": PRICE, "status": "pending", "ts": time.time()})
        flash("Payment submit ho gaya. Admin 24 ghante ke andar approve/reject karega.", "ok")
    return redirect(url_for("bot_page", bid=bid))

def use_code(code):
    with db.tx():
        c = db.get("giftcodes", code)
        if not c or c.get("uses_left", 0) <= 0: return False
        db.update("giftcodes", code, uses_left=c["uses_left"] - 1); return True

@app.route("/bots/<bid>/gift", methods=["POST"])
@login_required
def bot_gift(bid):
    b = get_bot(bid)
    if not b.get("approved"): flash("Bot approve hone ke baad gift code lagao.", "err")
    elif use_code(request.form["code"].strip().upper()): db.update("bots", bid, plan="permanent", expires_at=None); flash("Gift code applied - permanent hosting active!", "ok")
    else: flash("Invalid ya used gift code.", "err")
    return redirect(url_for("bot_page", bid=bid))

# ---------- admin ----------
def dir_mb(p): return sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(p) for f in fs if os.path.isfile(os.path.join(r, f))) / 1048576

@app.route("/admin")
@admin_required
def admin():
    tab, d = request.args.get("tab", "overview"), {}
    srt = lambda l, k="ts": sorted(l, key=lambda x: -x.get(k, 0))
    if tab == "overview":
        bots, pays = db.all("bots"), db.all("payments"); w = db.get("system", "worker") or {}
        free = shutil.disk_usage(db.DATA).free / 1048576
        d = {"users": len(db.all("users")), "bots": len(bots), "running": sum(b.get("state") == "running" for b in bots),
             "pend_bots": sum(not b.get("approved") for b in bots), "pend_pay": sum(p["status"] == "pending" for p in pays),
             "revenue": sum(p["amount"] for p in pays if p["status"] == "approved"), "worker_ok": time.time() - w.get("ts", 0) < 30,
             "storage_mb": round(dir_mb(db.DATA)), "free_mb": round(free), "errors": [b for b in bots if b.get("last_error")][:8]}
    elif tab == "users": d["rows"] = srt(db.all("users"), "created")
    elif tab == "bots": d["rows"] = srt(db.all("bots"), "created")
    elif tab == "payments": d["rows"] = srt(db.all("payments"))
    elif tab == "templates": d["rows"] = db.all("templates")
    elif tab == "gifts": d["rows"] = srt(db.all("giftcodes"), "created")
    elif tab == "announce": d["rows"] = srt(db.all("announcements"))
    elif tab == "logs": d["rows"] = srt(db.all("admin_logs"))[:150]
    return render_template("admin.html", tab=tab, d=d)

@app.route("/admin/backup", methods=["POST"])
@admin_required
def admin_backup():
    import sqlite3
    tmp = tempfile.mkdtemp(); snap = f"{tmp}/zad.db"
    dst = sqlite3.connect(snap); db.conn().backup(dst); dst.close()
    out = f"{tmp}/backup.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(snap, "zad.db")
        for f in os.listdir(db.ZIPS): z.write(f"{db.ZIPS}/{f}", f"zips/{f}")
    alog("backup downloaded")
    return send_file(out, as_attachment=True, download_name=f"zad-backup-{time.strftime('%Y%m%d-%H%M')}.zip")

@app.route("/admin/template", methods=["POST"])
@admin_required
def admin_template():
    f, back = request.files.get("zip"), redirect(url_for("admin", tab="templates"))
    if not f or not f.filename.lower().endswith(".zip"): flash("ZIP select karo.", "err"); return back
    data = f.read()
    try: an = analyzer.analyze(data)
    except analyzer.BadZip as e: flash(str(e), "err"); return back
    tid = db.new_id(); db.save_file(f"t_{tid}.zip", data)
    db.put("templates", tid, {"title": request.form["title"].strip()[:50] or "Untitled", "category": request.form.get("category", "General").strip()[:30] or "General",
                              "desc": request.form.get("desc", "")[:300], "zip_path": f"t_{tid}.zip", "size": len(data), "analysis": an, "active": True, "created": time.time()})
    alog("template upload: " + request.form["title"]); flash("Template upload + analyze ho gaya. Fields check kar lo.", "ok"); return back

@app.route("/admin/template/<tid>/<action>", methods=["POST"])
@admin_required
def admin_template_act(tid, action):
    t = db.get("templates", tid)
    if not t: abort(404)
    if action == "delete": db.del_file(t["zip_path"]); db.delete("templates", tid)
    elif action == "toggle": db.update("templates", tid, active=not t["active"])
    elif action == "fields":
        import json
        try:
            fl = json.loads(request.form["fields"]); assert isinstance(fl, list) and all("key" in x for x in fl)
            t["analysis"]["fields"] = fl; db.put("templates", tid, t); flash("Fields updated (naye bots ke liye).", "ok")
        except Exception: flash("Invalid JSON.", "err")
    alog(f"template {action}: {tid}"); return redirect(url_for("admin", tab="templates"))

@app.route("/admin/payment/<pid>/<action>", methods=["POST"])
@admin_required
def admin_payment(pid, action):
    p = db.get("payments", pid) or abort(404)
    if action == "approve":
        db.update("payments", pid, status="approved", decided=time.time())
        db.update("bots", p["bot_id"], plan="permanent", expires_at=None, approved=True, suspended=False)
    elif action == "reject": db.update("payments", pid, status="rejected", decided=time.time())
    alog(f"payment {action}: {p['utr']} {p['email']}"); return redirect(url_for("admin", tab="payments"))

@app.route("/admin/user/<uid>/<action>", methods=["POST"])
@admin_required
def admin_user(uid, action):
    db.update("users", uid, status="suspended" if action == "suspend" else "active"); alog(f"user {action}: {uid}")
    return redirect(url_for("admin", tab="users"))

@app.route("/admin/bot/<bid>/<action>", methods=["POST"])
@admin_required
def admin_bot(bid, action):
    b = db.get("bots", bid) or abort(404); u = {}
    if action == "approve": u = {"approved": True, "expires_at": time.time() + TRIAL_SEC}
    elif action == "reject":
        db.delete("bots", bid); db.del_file(b["zip_path"]) if b.get("own_zip") else None; alog(f"bot reject/delete: {bid}"); return redirect(url_for("admin", tab="bots"))
    elif action == "suspend": u = {"suspended": True, "desired": "stopped"}
    elif action == "restore": u = {"suspended": False}
    elif action == "start": u = {"desired": "running"}
    elif action == "stop": u = {"desired": "stopped"}
    elif action == "restart": u = {"desired": "running", "restart_req": time.time()}
    elif action == "extend":
        days = max(1, min(int(request.form.get("days", 1)), 365)); u = {"expires_at": max(b.get("expires_at") or 0, time.time()) + days * 86400}
    elif action == "permanent": u = {"plan": "permanent", "expires_at": None, "approved": True}
    elif action == "pkg":
        p = request.form.get("pkg", "").strip()
        if re.fullmatch(r"[A-Za-z0-9_.\-]+(==[\w.]+)?", p): u = {"approved_packages": sorted(set(b.get("approved_packages", []) + [p]))}
    db.update("bots", bid, **u); alog(f"bot {action}: {bid}"); return redirect(url_for("admin", tab="bots"))

@app.route("/admin/gift", methods=["POST"])
@admin_required
def admin_gift():
    n, uses = max(1, min(int(request.form.get("count", 1)), 50)), max(1, min(int(request.form.get("uses", 1)), 1000))
    for _ in range(n):
        c = "ZAD-" + secrets.token_hex(2).upper() + "-" + secrets.token_hex(2).upper()
        db.put("giftcodes", c, {"code": c, "uses_left": uses, "uses": uses, "created": time.time()})
    alog(f"gift codes x{n}"); return redirect(url_for("admin", tab="gifts"))

@app.route("/admin/announce", methods=["POST"])
@admin_required
def admin_announce():
    if request.form.get("delete"): db.delete("announcements", request.form["delete"])
    else: db.add("announcements", {"text": request.form["text"][:300], "ts": time.time()})
    return redirect(url_for("admin", tab="announce"))

@app.route("/healthz")
def healthz(): return "ok"

if __name__ == "__main__": app.run(debug=True)
