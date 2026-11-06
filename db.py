"""Tiny document store on SQLite (replaces Firebase) + ZIP file storage on the Render disk."""
import os, json, sqlite3, threading, uuid, secrets, contextlib

DATA = os.environ.get("DATA_DIR", "/data")
DB_PATH, ZIPS = f"{DATA}/db/zad.db", f"{DATA}/zips"
_t = threading.local()

def conn():
    c = getattr(_t, "c", None)
    if c is None:
        c = _t.c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA synchronous=NORMAL")
    return c

def init():
    os.makedirs(f"{DATA}/db", exist_ok=True); os.makedirs(ZIPS, exist_ok=True)
    c = conn()
    c.execute("CREATE TABLE IF NOT EXISTS docs(col TEXT, id TEXT, data TEXT, PRIMARY KEY(col, id))")
    c.execute("CREATE INDEX IF NOT EXISTS i_uid ON docs(col, json_extract(data, '$.uid'))")
    os.chmod(DB_PATH, 0o666)   # folder itself is 700 + owned by the web user, so bots cannot reach it

def secret():
    if os.environ.get("SECRET_KEY"): return os.environ["SECRET_KEY"]
    p = f"{DATA}/db/secret.key"
    if not os.path.exists(p):
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666); os.write(fd, secrets.token_hex(32).encode()); os.close(fd)
        except FileExistsError: pass
    return open(p).read().strip()

@contextlib.contextmanager
def tx():
    c = conn()
    if c.in_transaction: yield c; return
    c.execute("BEGIN IMMEDIATE")
    try: yield c; c.execute("COMMIT")
    except BaseException: c.execute("ROLLBACK"); raise

def new_id(): return uuid.uuid4().hex[:20]
def _row(i, data): d = json.loads(data); d["id"] = i; return d
def get(col, i):
    r = conn().execute("SELECT data FROM docs WHERE col=? AND id=?", (col, i)).fetchone()
    return _row(i, r[0]) if r else None
def put(col, i, d):
    conn().execute("INSERT OR REPLACE INTO docs VALUES(?,?,?)", (col, i, json.dumps({k: v for k, v in d.items() if k != "id"})))
def add(col, d): i = new_id(); put(col, i, d); return i
def update(col, i, **kw):
    with tx():
        d = get(col, i)
        if d is None: return False
        d.update(kw); put(col, i, d); return True
def delete(col, i): conn().execute("DELETE FROM docs WHERE col=? AND id=?", (col, i))
def all(col): return [_row(i, d) for i, d in conn().execute("SELECT id, data FROM docs WHERE col=?", (col,))]
def where(col, field, val):
    return [_row(i, d) for i, d in conn().execute("SELECT id, data FROM docs WHERE col=? AND json_extract(data, ?)=?", (col, "$." + field, val))]

def save_file(name, data):
    with open(f"{ZIPS}/{name}", "wb") as f: f.write(data)
def read_file(name):
    with open(f"{ZIPS}/{name}", "rb") as f: return f.read()
def del_file(name):
    try: os.remove(f"{ZIPS}/{name}")
    except OSError: pass
