"""Parse a deliberately narrow, documented subset of OpenSSH log messages."""
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

MESSAGE = re.compile(r"\b(?P<action>Failed|Accepted) (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)\b")
PREFIX = re.compile(r"^(?P<stamp>\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<body>.*)$")
MONTHS = {name: i for i, name in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}

@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    user: str
    ip: str
    action: str
    method: str
    line: int


def timestamp(value, year=None):
    if re.match(r'^\d{4}-', value):
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    else:
        if year is None:
            raise ValueError('Traditional syslog timestamps require --year')
        month, day, clock = value.split()
        h, m, s = map(int, clock.split(':'))
        dt = datetime(year, MONTHS[month], int(day), h, m, s)
    # Naive input is explicitly interpreted as UTC, never host-local time.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_line(raw, number, year=None):
    """Return an Event or None for unsupported/malformed input."""
    raw = raw.strip()
    stamp_override = None
    if raw.startswith('{'):
        try:
            record = json.loads(raw)
            if not isinstance(record, dict):
                return None
            stamp_override = record.get('timestamp')
            raw = record.get('full_log', '')
            if not isinstance(raw, str):
                return None
        except (ValueError, TypeError):
            return None
    prefix = PREFIX.match(raw)
    if not prefix:
        return None
    match = MESSAGE.fullmatch(prefix['body'].strip())
    # OpenSSH commonly appends protocol / key fingerprint details.
    if not match:
        match = MESSAGE.match(prefix['body'])
    if not match:
        return None
    try:
        dt = timestamp(stamp_override or prefix['stamp'], year)
        ip = str(ipaddress.ip_address(match['ip']))
        if not 1 <= int(match['port']) <= 65535:
            return None
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    return Event(dt, prefix['host'], match['user'], ip,
                 match['action'].lower(), match['method'], number)


def read_events(path, year=None):
    events = []
    lines = ignored = 0
    with open(path, encoding='utf-8', errors='replace') as stream:
        for lines, raw in enumerate(stream, 1):
            event = parse_line(raw, lines, year)
            if event is None:
                ignored += 1
            else:
                events.append(event)
    events.sort(key=lambda event: (event.timestamp, event.line))
    return events, {'total_lines': lines, 'parsed_events': len(events), 'ignored_lines': ignored}
