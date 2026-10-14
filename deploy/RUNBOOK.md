> **Superseded by `CT105 Changes.md`** (repo root): no new subdomains; the witness is served at `witness.jrushvj.dev/custody/`.

# Integration runbook: Banking-system-fullstack on ct105 + witness on Oracle

Tested: both installers on a clean Linux box, and the agent against this app (their compose, real API,
2FA customer) — 59/59 records verified, zero false alarms, history and balance edits caught in 16 s.
Nothing in the banking app or the existing Node witness is changed.

**Choices:** Layer 3 = dry run on ct105 (detected and shown, lockout only recorded). Layer 1 protects
`/var/log/bank-demo` only. Our witness = new service on Oracle `127.0.0.1:8810`.

Paste each step's last few output lines back to Claude before moving on.

## 1 · Oracle VPS: our witness (Jaganath, ~5 min)
```bash
cd ~ && git clone https://github.com/JeevikaS-19/cybersec.git custody && cd custody
sudo PORT=8810 bash deploy/install-witness.sh          # expect: "witness up on 127.0.0.1:8810"
sudo ls /var/lib/custody-witness/shares/                # 3 share files: give one to each key holder, then delete
```
Add a Cloudflare tunnel route **custody.jrushvj.dev → http://127.0.0.1:8810** (keep the existing
`witness.jrushvj.dev → 8787` rule). Check from any browser: `https://custody.jrushvj.dev/` shows the auditor view.
Does not touch `banking-witness` (8787) or `coc-witness` (8800). Memory capped at 200 MB.

## 2 · ct105: read-only database user (Jaganath, 1 min)
In the banking app's folder (its compose project):
```bash
docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c \
  "CREATE ROLE coc_reader LOGIN PASSWORD '<pick one>'; GRANT SELECT ON transactions, accounts TO coc_reader;"
```
(`$DB_USER` = the postgres user from the app's `.env`.) Read-only: our agent can look, never change.

## 3 · ct105: agent + tripwire + backstop (~5 min)
```bash
cd ~ && git clone https://github.com/JeevikaS-19/cybersec.git custody && cd custody
sudo COC_PLATFORM_CONFIG=/opt/coc/config/platform.team-bank.yaml \
     WITNESS_URL=https://custody.jrushvj.dev \
     COC_DB_DSN='postgresql://coc_reader:<password>@127.0.0.1:5432/bankingsystem' \
     COC_PROTECTED_PATH=/var/log/bank-demo COC_L3_DRY_RUN=1 \
     bash deploy/install-log-server.sh                  # expect: "installed: protected /var/log/bank-demo, Layer 3 dry_run=true"
sudo bash -c 'cd /opt/coc && PYTHONPATH=/opt/coc venv/bin/python -m layers.l1_tripwire.profiles add firewallcrew-bank'
                                                        # type the team's profile-id (kept as a hash only)
systemctl status coc-agent coc-backstop --no-pager | grep Active
```
If PostgreSQL isn't published on `127.0.0.1:5432` on the host, use the address from the app's compose file.

## 4 · Verify (together)
1. `https://custody.jrushvj.dev/`: **Connected**, records verified = the app's completed transactions, all green.
2. Make a deposit and a transfer in the bank website → records verified goes up, no alerts.
3. Layer 1: `echo test > /var/log/bank-demo/app.log` (as root), then as a normal user `nano /var/log/bank-demo/app.log`
   → Layer 1 caught; `nano --<profile-id> /var/log/bank-demo/app.log` → allowed row.
4. Layer 2 (reversible): note a transaction's amount, change it, watch Record #N appear, put it back:
   ```bash
   docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "SELECT id, amount FROM transactions ORDER BY id DESC LIMIT 1;"
   docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "UPDATE transactions SET amount = 0.01 WHERE id = <id>;"
   # ...after the page shows it:
   docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "UPDATE transactions SET amount = <old> WHERE id = <id>;"
   ```
   The alert stays on the record (evidence); that's expected.
5. Layer 3 (dry run): `sudo iptables -I OUTPUT -d <custody.jrushvj.dev IP> -j DROP` for 50 s, then remove the rule
   (`sudo iptables -D OUTPUT ...`) → page shows quarantined; the server records the lockout commands but runs none.
   Approve with two shares.

## Undo everything on ct105
```bash
sudo systemctl disable --now coc-agent coc-backstop
sudo rm -rf /opt/coc /opt/trip /etc/profile.d/coc-*.sh /etc/coc /var/lib/coc /var/spool/coc /etc/systemd/system/coc-*.service
docker compose exec -T postgres psql -U "$DB_USER" -d bankingsystem -c "DROP ROLE coc_reader;"
```
