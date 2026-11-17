# Architecture and design decisions

The CLI validates options, the parser creates normalized events, the detector correlates them, and the reporting module renders one result in three formats. Modules depend only on the Python standard library.

## Event model

Each event has a UTC timestamp, destination host, account, normalized source IP, result (`failed` or `accepted`), authentication method and input line number. The raw message is not embedded into the dashboard. Sorting ensures that shuffled log lines produce the same chronological detections. For equal timestamps, original input order determines correlation.

## Detection state

For each `(host, IP)` pair, a deque stores recent failed authentications. Before processing an event, failures older than the configured inclusive window are removed. Two state flags suppress repeated burst/account alerts while their conditions remain true. Successful logins are matched to failures for the same account. A matching success clears that account's failures, allowing a later episode to be investigated separately.

This grouping avoids incorrectly correlating different destination machines behind a shared log collector. It still cannot distinguish multiple people behind one NAT source IP. Password and public-key failures contribute to the same authentication-failure threshold.

## Trust and limits

- Alerts are hypotheses, not verdicts. A medium alert may be a typo, automation error or authorized root login.
- One source IP is assumed to identify one source for correlation; distributed guessing is not detected.
- Hostnames are taken from input and are not authenticated. Duplicate hostnames can mix devices.
- Supported logs must include timestamp, hostname and `sshd` prefix. Journal short formats and arbitrary Wazuh decoders are not supported.
- Wazuh wrapper timestamp takes precedence over the embedded timestamp; ingestion delays can affect the correlation window.
- Unrecognized, malformed and blank lines share one ignored counter. Always review that count.
- All parsed events are held in memory and sorted (O(n log n)). Unique-user counts scan each active window. This version is for manageable offline lab files; no large-scale throughput claim is made.
- Duplicate lines are not deduplicated. Only analyze one canonical export of each event.
- Traditional syslog has neither year nor timezone. `--year` applies one year to every such line, and naive timestamps are assumed UTC. Normalize other timezones and year rollovers first.
- Reports overwrite three fixed files in the chosen output directory. Use a separate directory per investigation.

## Future work

Potential extensions: strict parse diagnostics, bounded streaming mode, host identity from Wazuh agent IDs, optional allowlists with audit trails, statistical baselines evaluated against labeled data, and broader OpenSSH/journal formats. These are roadmap items, not current features.
