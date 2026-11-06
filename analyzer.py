"""Static analyzer for bot ZIPs. It NEVER executes uploaded code - it only reads it."""
import ast, io, os, re, sys, zipfile, shutil

class BadZip(Exception): pass

MAX_FILES, MAX_TOTAL, MAX_PY = 3000, 120 * 1024 * 1024, 1_000_000
TOKEN_RE = re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{34,36}\b")
CFG = re.compile(r"(TOKEN|ADMIN|OWNER|CHAT_?ID|CHANNEL|GROUP|FORCE_?SUB|JOIN|LINK|API_?URL|API_?KEY|API_?HASH|API_?ID|SECRET|PASSWORD|WELCOME|WEBHOOK|USERNAME|_URL$)", re.I)
ENV = re.compile(r"""(?:getenv|environ\.get)\(\s*['"]([A-Za-z_]\w*)['"]\s*(,)?|environ\[\s*['"]([A-Za-z_]\w*)['"]\s*\]""")
ENTRIES = ["main.py", "bot.py", "app.py", "run.py", "start.py", "index.py"]
RUN_MARK = re.compile(r"run_polling|infinity_polling|\.polling\(|executor\.start_polling|start_polling|\.run_until_disconnected|bot\.run\(|client\.run\(|\.idle\(")
DANGER = [(r"\bos\.system\(", "os.system use hota hai"), (r"\bsubprocess\b", "subprocess use hota hai"),
          (r"\beval\(|\bexec\(", "eval/exec use hota hai"), (r"\bshutil\.rmtree\(", "folder delete (rmtree)"),
          (r"__import__\(", "dynamic import"), (r"\bsocket\.", "raw socket use hota hai"),
          (r"/proc/|/etc/passwd|environ\b.*FIREBASE", "system file / secret access ki koshish")]
ALIAS = {"telebot": "pyTelegramBotAPI", "telegram": "python-telegram-bot", "PIL": "pillow", "bs4": "beautifulsoup4",
         "yaml": "pyyaml", "dotenv": "python-dotenv", "cv2": "opencv-python-headless", "dateutil": "python-dateutil",
         "whois": "python-whois", "Crypto": "pycryptodome", "discord": "discord.py", "jwt": "pyjwt"}
ALLOWED = {x.lower() for x in """pyTelegramBotAPI python-telegram-bot aiogram pyrogram tgcrypto telethon discord.py requests aiohttp
httpx beautifulsoup4 lxml pillow pyyaml python-dotenv flask schedule apscheduler pytz python-dateutil phonenumbers qrcode colorama
tqdm emoji psutil gtts pymongo dnspython python-whois user-agents fake-useragent aiofiles cryptography pycryptodome pyjwt
opencv-python-headless numpy pandas openpyxl yt-dlp instaloader""".split()} | {
    x.strip().lower() for x in os.environ.get("EXTRA_PACKAGES", "").split(",") if x.strip()}

def norm(n): return re.sub(r"[-_.]+", "-", n.lower())
ALLOWED = {norm(x) for x in ALLOWED}

def open_zip(data):
    try: zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile: raise BadZip("Valid ZIP file upload karo.")
    infos = zf.infolist()
    if len(infos) > MAX_FILES: raise BadZip("ZIP mein files bahut zyada hain.")
    if sum(i.file_size for i in infos) > MAX_TOTAL: raise BadZip("ZIP unzip hone par bahut bada hai.")
    for i in infos:
        parts = i.filename.replace("\\", "/").split("/")
        if i.filename.startswith(("/", "\\")) or ".." in parts: raise BadZip(f"Unsafe path: {i.filename}")
        if (i.external_attr >> 16) & 0o170000 == 0o120000: raise BadZip("Symlink wali ZIP allowed nahi hai.")
    return zf

def find_root(names):
    files = [n for n in names if not n.endswith("/")]
    tops = {n.split("/")[0] for n in files}
    return tops.pop() + "/" if len(tops) == 1 and all("/" in n for n in files) else ""

def safe_extract(zf, dest):
    root = find_root(zf.namelist())
    os.makedirs(dest, exist_ok=True)
    for i in zf.infolist():
        if i.is_dir(): continue
        rel = i.filename[len(root):]
        if not rel or "__MACOSX" in rel or rel.endswith(".pyc"): continue
        out = os.path.join(dest, rel)
        if not os.path.abspath(out).startswith(os.path.abspath(dest) + os.sep): continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with zf.open(i) as s, open(out, "wb") as t: shutil.copyfileobj(s, t)

def ftype(k, v=None):
    K = k.upper()
    if re.search(r"TOKEN|SECRET|KEY|HASH|PASSWORD", K): return "secret"
    if K.endswith("URL"): return "url"
    if re.search(r"(^|_)IDS?$", K) or isinstance(v, int): return "number"
    return "text"

def field(k, mode, file, required=True, vtype="str", v=None):
    return {"key": k, "label": k.replace("_", " ").title(), "type": ftype(k, v), "required": required,
            "mode": mode, "file": file, "vtype": vtype}

def analyze(data):
    zf = open_zip(data)
    names = [i.filename for i in zf.infolist() if not i.is_dir()]
    root = find_root(names)
    rel = lambda n: n[len(root):]
    pys = {rel(n): zf.read(n)[:MAX_PY].decode("utf-8", "ignore") for n in names if n.endswith(".py")}
    if not pys: raise BadZip("ZIP mein koi .py file nahi mili.")
    local = {p.split("/")[0].removesuffix(".py") for p in pys} | {rel(n).split("/")[0].removesuffix(".py") for n in names}
    fields, imps, cmds, warns = {}, set(), set(), []
    for path, src in pys.items():
        for pat, msg in DANGER:
            if re.search(pat, src): warns.append(f"{path}: {msg}")
        for m in ENV.finditer(src):
            k = m.group(1) or m.group(3)
            fields.setdefault(k, field(k, "env", path, required=not m.group(2)))
        try: tree = ast.parse(src)
        except SyntaxError as e: warns.append(f"{path}: syntax error line {e.lineno}"); continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): imps |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module: imps.add(node.module.split(".")[0])
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                k, v = node.targets[0].id, node.value
                if not CFG.search(k) or k in fields: continue
                if isinstance(v, ast.Constant) and isinstance(v.value, (str, int)) and not isinstance(v.value, bool):
                    fields[k] = field(k, "code", path, vtype="int" if isinstance(v.value, int) else "str", v=v.value)
                elif isinstance(v, (ast.List, ast.Tuple)) and all(isinstance(e, ast.Constant) for e in v.elts):
                    fields[k] = field(k, "code", path, vtype="list")
        for pat in (r"CommandHandler\(\s*['\"](\w+)", r"\bCommand\(\s*['\"](\w+)", r"pattern\s*=\s*r?['\"]\^?/(\w+)"):
            cmds |= set(re.findall(pat, src))
        for grp in re.findall(r"commands\s*=\s*\[([^\]]*)\]", src): cmds |= set(re.findall(r"['\"](\w+)['\"]", grp))
    tok = next((p for p, s in pys.items() if TOKEN_RE.search(s)), None)
    if tok and not any("TOKEN" in k.upper() for k in fields): fields["BOT_TOKEN"] = field("BOT_TOKEN", "literal", tok)
    entry = next((e for e in ENTRIES if e in pys), None) or next((p for p, s in pys.items() if RUN_MARK.search(s)), None) \
        or next((p for p, s in pys.items() if "__main__" in s), sorted(pys)[0])
    # dependencies: requirements.txt (filtered) + imports, only from allowlist
    pk, unknown, blocked = {}, set(), []
    req = next((zf.read(n).decode("utf-8", "ignore") for n in names if rel(n) == "requirements.txt"), "")
    for line in req.splitlines():
        line = line.split("#")[0].strip()
        if not line: continue
        if line.startswith("-") or "://" in line or "@" in line: blocked.append(line); continue
        name = norm(re.split(r"[=<>!~\[; ]", line)[0])
        (pk.__setitem__(name, line) if name in ALLOWED else unknown.add(line))
    std = set(sys.stdlib_module_names)
    for i in sorted(imps - std - local):
        name = norm(ALIAS.get(i, i))
        if name in pk: continue
        (pk.__setitem__(name, ALIAS.get(i, i)) if name in ALLOWED else unknown.add(i))
    order = {"BOT_TOKEN": 0}
    flist = sorted(fields.values(), key=lambda f: (order.get(f["key"], 1), "TOKEN" not in f["key"].upper(), f["key"]))
    return {"entry": entry, "fields": flist, "packages": sorted(pk.values()), "unknown": sorted(unknown),
            "blocked": blocked, "commands": sorted(cmds)[:40], "warnings": warns[:30], "py_files": len(pys)}
