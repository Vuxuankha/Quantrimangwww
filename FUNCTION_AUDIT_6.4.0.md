# NetworkAutomation UI 6.4.0 - Functional Reliability Upgrade

Audit date: 2026-10-05

## Functional upgrades

1. **Persistent machine presence state**
   - Stores current state per managed IP: Online / Offline / Unknown.
   - Stores last-seen time, offline-since time, discovery source, and consecutive missed checks.
   - State survives browser refresh/re-login because it is kept in SQLite support tables.

2. **Presence transition history**
   - Records Online -> Unknown -> Offline and recovery transitions.
   - Dashboard shows recent machine state changes, not only a point-in-time count.
   - History is bounded to the newest 5,000 transitions.

3. **False-offline protection**
   - ICMP remains combined with ARP/neighbor evidence.
   - A single isolated failed probe after a known-good Online state becomes Unknown first.
   - A repeated miss becomes Offline, reducing false alarms from transient packet loss.

4. **Identity Guard**
   - Detects one normalized MAC address observed on multiple IP addresses.
   - Dashboard shows the current identity-conflict count.
   - Read-only detection: no automatic delete/merge is performed.

5. **Function Audit coverage**
   - Quản trị > Kiểm tra chức năng now reports Live Machine Presence and Identity Guard readiness.

## Checks performed

- Python source compile: PASS.
- Main JavaScript syntax: PASS.
- Presence-state transition simulation on disposable SQLite DB: PASS.
- MAC multi-IP conflict detection on disposable SQLite DB: PASS.
- No existing user database was modified during build tests.
