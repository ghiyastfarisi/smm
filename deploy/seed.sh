#!/bin/sh
# Demo data through mmctl local mode. Safe to re-run: existing items are skipped.
mm() { mmctl --local "$@" >/dev/null 2>&1 || true; }
P='Demo#12345'
# Slack-like: show full names by default (users can switch to usernames in their display settings).
mm config set TeamSettings.TeammateNameDisplay full_name
mm team create --name demo --display-name "Demo"
mm user create --email admin@smm.demo --username admin --password "$P" --system-admin --email-verified
mm user create --email ani@smm.demo --username ani --password "$P" --firstname Ani --lastname Wijaya --email-verified
mm user create --email budi@smm.demo --username budi --password "$P" --firstname Budi --lastname Santoso --email-verified
mm team users add demo admin ani budi
mm channel create --team demo --name mrpostman --display-name "mrpostman"
mm channel users add demo:mrpostman admin ani budi
mm channel users add demo:town-square admin ani budi
echo "seed done: ani / budi / admin, password $P"
