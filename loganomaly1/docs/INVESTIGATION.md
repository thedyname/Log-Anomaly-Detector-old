# Synthetic investigation walkthrough

Run the demo with default settings. Expected output: 12 SSH events, 1 ignored service message, 4 alerts.

| Alert | Trigger | Evidence lines | Interpretation |
|---|---|---|---|
| AL-0001 | 10:00:40 UTC, 192.0.2.10, lab-web | 2–6 | Five failed authentications for admin within 40 seconds |
| AL-0002 | 10:00:50 UTC, 192.0.2.10, lab-web | 2–7 | Successful admin authentication after those failures |
| AL-0003 | 10:10:30 UTC, 203.0.113.7, lab-db | 8–11 | Four distinct accounts targeted within 30 seconds |
| AL-0004 | 11:00:00 UTC, 2001:db8::20, lab-db | 12 | Successful public-key authentication as root |

## Analyst workflow

1. Confirm the timestamps, source host, IP and account against original evidence.
2. Check whether the account owner or an administrator expected the activity.
3. Review surrounding authentication, session and command/audit records in the lab.
4. Identify the affected host and whether there was privileged activity after login.
5. Record a conclusion: expected activity, suspicious activity requiring escalation, or insufficient evidence.
6. Recommend an appropriate response based on verified facts. This detector itself does not block IPs or modify accounts.

The demo deliberately illustrates suspicious patterns. It does not prove any real compromise. The normal sample should generate zero alerts; that does not prove all possible benign behavior is correctly classified.

## Learning experiments

- Set `--threshold 6`: the five-failure episode should no longer trigger burst or correlated-success alerts.
- Move a failure outside the five-minute window and observe the change.
- Change the successful account from admin to another user: correlation should disappear.
- Reorder lines: time-based behavior should remain, but evidence line numbers change.
- Repeat an input line: counts increase because the detector does not deduplicate.
