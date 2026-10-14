# CT105 Changes: integrate Chain of Custody with the banking app

**For:** Jerush (and the assistant helping him). **From:** Jeev. Work through the parts in order, paste the
output asked for at each **Report back** to Jeev, and stop at the first unexpected result.

## Context
- **Banking app:** `jtr-0901/Banking-system-fullstack` (Node + PostgreSQL), running on **ct105** via Docker Compose
  (project `banking-system`, checkout `/opt/chain-of-custody-firewallcrew/banking-system`, Postgres on `127.0.0.1:5432`).
- **Chain of Custody:** `https://github.com/JeevikaS-19/cybersec`. An agent on ct105 reads the bank's transactions
  through a **read-only** database user, seals them, and sends them to our witness on the Oracle VPS, which checks them.
  Already tested against this exact app (real API, 2FA customer): every record verified, no false alarms, edits caught in ~16 s.

## Rules (do not break these)
- **No new subdomains.** Only `witness.jrushvj.dev` and `bank.jrushvj.dev` exist. Our witness is served under the
  **path** `witness.jrushvj.dev/custody/` on the existing hostname.
- **Do not change** the banking app's code, its compose file, its database data, or its PostgreSQL volume.
- **Do not touch** the Node witness (`banking-witness`, `127.0.0.1:8787`) or the legacy `coc-witness` (port 8800).
- **Layer 3 runs in dry run on ct105:** a quarantine is detected and shown; the lockout commands are only recorded,
  never run. Nobody gets locked out of ct105.
- **Layer 1 is limited to `/var/log/bank-demo`**, and editors only trip inside it (`editors_scope: protected`),
  so normal `nano`/`vim` use elsewhere on ct105 is unaffected.
- Never print, log or commit passwords, the profile-id or the key-holder shares.

---

## Part A · Oracle VPS: our witness behind `witness.jrushvj.dev/custody` (prerequisite)

1. Install it next to the existing services (own user, own port, 200 MB memory cap):
   ```bash
   cd ~ && git clone https://github.com/JeevikaS-19/cybersec.git custody && cd custody
   sudo PORT=8810 PREFIX=/custody bash deploy/install-witness.sh
   ```
   Expect: `witness up on 127.0.0.1:8810`.
2. Cloudflare tunnel: add a **path rule on the existing hostname**, placed **above** the current
   `witness.jrushvj.dev` rule (cloudflared matches top to bottom), then restart `cloudflared`:
   ```yaml
   - hostname: witness.jrushvj.dev
     path: ^/custody(/.*)?$
     service: http://127.0.0.1:8810
   - hostname: witness.jrushvj.dev          # existing rule, unchanged
     service: http://127.0.0.1:8787
   ```
3. Check: `https://witness.jrushvj.dev/custody/` shows the Chain of Custody auditor view (status "Waiting"), and
   `https://witness.jrushvj.dev/` still shows the existing Node witness.
4. Key-holder shares: `sudo ls /var/lib/custody-witness/shares/` → three files (SOC lead, Auditor, Compliance officer).
   Give one to each holder privately, then delete them from the server.

**Report back:** the install output's last 3 lines, and confirmation both URLs load.

## Part B · ct105: read-only database user

In `/opt/chain-of-custody-firewallcrew/banking-system`:
```bash
set -a; . ./.env; set +a          # loads DB_USER (do not echo it)
docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c \
  "CREATE ROLE coc_reader LOGIN PASSWORD '<choose a strong password>'; GRANT SELECT ON transactions, accounts TO coc_reader;"
docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c \
  "SELECT has_table_privilege('coc_reader','transactions','UPDATE') AS can_update;"   # must be: f
```
**Report back:** `CREATE ROLE`, `GRANT`, and `can_update = f`.

## Part C · ct105: agent, tripwire and backstop

```bash
cd ~ && git clone https://github.com/JeevikaS-19/cybersec.git custody && cd custody
sudo COC_PLATFORM_CONFIG=/opt/coc/config/platform.team-bank.yaml \
     WITNESS_URL=https://witness.jrushvj.dev/custody \
     COC_DB_DSN='postgresql://coc_reader:<the password from Part B>@127.0.0.1:5432/bankingsystem' \
     COC_PROTECTED_PATH=/var/log/bank-demo COC_EDITORS_SCOPE=protected COC_L3_DRY_RUN=1 \
     bash deploy/install-log-server.sh
```
Expect: `installed: protected /var/log/bank-demo, Layer 3 dry_run=true`. Then register the team's profile-id
(Jeev gives it to you in person; it is stored only as a hash):
```bash
sudo bash -c 'cd /opt/coc && PYTHONPATH=/opt/coc venv/bin/python -m layers.l1_tripwire.profiles add firewallcrew-bank'
systemctl is-active coc-agent coc-backstop        # both: active
sudo journalctl -u coc-agent -n 5 --no-pager      # no "unavailable" / "unreachable" lines
```
If Postgres is not published on `127.0.0.1:5432` on the host, use the address from the app's compose file.

**Report back:** the install's last line, `systemctl is-active` output, and the last 5 agent log lines.

## Part D · Verify together (with Jeev)
1. `https://witness.jrushvj.dev/custody/` → **Connected**, "Records verified" equals the app's completed transactions,
   all three cards green.
2. Make a deposit and a transfer on `bank.jrushvj.dev` → records verified goes up, no alert.
3. Layer 1: `echo "txn demo" | sudo tee /var/log/bank-demo/app.log`; as a normal user
   `nano /var/log/bank-demo/app.log` → Layer 1 caught; `nano --<profile-id> /var/log/bank-demo/app.log` → allowed row.
4. Layer 2, reversible (one demo row only, never balances):
   ```bash
   docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "SELECT id, amount FROM transactions ORDER BY id DESC LIMIT 1;"
   docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "UPDATE transactions SET amount = 0.01 WHERE id = <id>;"
   # when the page shows "Record #N": put it back
   docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "UPDATE transactions SET amount = <old amount> WHERE id = <id>;"
   ```
   The alert stays on the record as evidence; that is expected.
5. Layer 3 (dry run): block ct105 → witness for ~50 s (e.g. `sudo iptables -I OUTPUT -p tcp --dport 443 -j DROP`,
   then `sudo iptables -D OUTPUT -p tcp --dport 443 -j DROP`) → page shows "quarantined"; ct105 records the lockout
   commands but runs none. After reconnecting, two holders paste their shares on the page to unlock.

## Rollback (removes everything from ct105)
```bash
sudo systemctl disable --now coc-agent coc-backstop
sudo rm -rf /opt/coc /opt/trip /etc/profile.d/coc-*.sh /etc/coc /var/lib/coc /var/spool/coc /etc/systemd/system/coc-*.service
sudo systemctl daemon-reload
docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "DROP ROLE coc_reader;"
```
On Oracle: `sudo systemctl disable --now custody-witness` and remove the `/custody` tunnel rule.
