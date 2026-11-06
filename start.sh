#!/bin/sh
# One container = web (unprivileged user) + worker (root, drops each bot to its own user)
D=${DATA_DIR:-/data}
mkdir -p "$D/db" "$D/zips" "$D/bots"
python -c "import db; db.init(); db.secret()"
chown -R zadweb:zadweb "$D/db" "$D/zips"; chmod 700 "$D/db" "$D/zips"; chmod 755 "$D" "$D/bots"
( while true; do python worker.py; echo "worker exited, restarting in 3s"; sleep 3; done ) &
exec gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 2 --threads 4 --timeout 120 --user zadweb --group zadweb
