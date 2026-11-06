# ZAD OSINT — Premium Bot Hosting
Developer: Mafia H4x Coder · SN Hacker · Brother: POKA BROO

Stack: Flask + SQLite + Render Disk. Firebase ki zarurat nahi. Ek hi Render service mein website aur bot-worker dono chalte hain.

## Render deploy
1. Is folder ki saari files GitHub repo (private) ke root mein push karo.
2. Render -> New -> Blueprint -> repo chuno (ya New -> Web Service -> Runtime Docker, plan Starter, Disk mount /data 5GB).
3. Env var: ADMIN_EMAIL = tumhara email (isi email se register karoge to admin banoge). Baaki render.yaml mein hain.
4. Deploy ke baad site kholo -> Register -> Admin menu -> Templates -> bot ZIP upload.

## Env vars
ADMIN_EMAIL, UPI_ID (default sunny8127@fam), PRICE (99), MAX_BOTS_PER_USER (5), BOT_MEM_MB (512), EXTRA_PACKAGES (comma list).
SECRET_KEY optional hai, na do to disk par auto-ban jati hai.

## Local test
DATA_DIR=./data INSECURE_COOKIES=1 ADMIN_EMAIL=you@x.com python worker.py   # terminal 1
DATA_DIR=./data INSECURE_COOKIES=1 ADMIN_EMAIL=you@x.com python app.py      # terminal 2

## Security
- Web process uploaded code kabhi run nahi karta. ZIP safe-extract hoti hai (path traversal, symlink, size limit).
- Bots worker mein chalte hain: har bot apna unix user + memory limit + clean environment. Database folder bots ko nahi dikhta.
- Sirf allowlist ke packages auto-install; baaki admin "Allow" kare. Admin ko code warnings (os.system, eval...) dikhte hain.
- Payment manual verify hota hai (UTR). Backup: Admin -> Overview -> Download backup.
