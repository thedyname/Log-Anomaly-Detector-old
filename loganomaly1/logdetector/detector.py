"""Deterministic, explainable sliding-window detections (not machine learning)."""
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta

@dataclass(frozen=True)
class Config:
    window_seconds: int = 300
    failure_threshold: int = 5
    user_threshold: int = 4

    def __post_init__(self):
        if self.window_seconds < 1 or self.failure_threshold < 2 or self.user_threshold < 2:
            raise ValueError('Window must be >= 1; thresholds must be >= 2')


def detect(events, config=Config()):
    """Group by destination host and source IP; expire failures before each event.

    Emit burst/spray alerts on false-to-true threshold transitions. A subsequent
    success is correlated only with failures for the SAME account in the window.
    """
    history = defaultdict(deque)
    active = defaultdict(set)
    alerts = []
    window = timedelta(seconds=config.window_seconds)

    def emit(rule, severity, event, evidence, explanation):
        alerts.append({
            'id': f'AL-{len(alerts)+1:04d}', 'rule': rule, 'severity': severity,
            'timestamp': event.timestamp.isoformat(), 'host': event.host,
            'source_ip': event.ip, 'user': event.user,
            'failure_count': sum(e.action == 'failed' for e in evidence),
            'users': sorted({e.user for e in evidence}),
            'evidence_lines': [e.line for e in evidence], 'explanation': explanation,
        })

    for event in sorted(events, key=lambda e: (e.timestamp, e.line)):
        key = (event.host, event.ip)
        queue = history[key]
        while queue and event.timestamp - queue[0].timestamp > window:
            queue.popleft()
        # Reset before appending: a later burst can retrigger after expiration.
        if len(queue) < config.failure_threshold:
            active[key].discard('SSH_FAILURE_BURST')
        if len({e.user for e in queue}) < config.user_threshold:
            active[key].discard('SSH_MULTI_ACCOUNT')
        if event.action == 'failed':
            queue.append(event)
            checks = [
                ('SSH_FAILURE_BURST', len(queue) >= config.failure_threshold,
                 f'At least {config.failure_threshold} failed SSH authentications within {config.window_seconds}s.'),
                ('SSH_MULTI_ACCOUNT', len({e.user for e in queue}) >= config.user_threshold,
                 f'Failed SSH authentications target at least {config.user_threshold} accounts within {config.window_seconds}s.'),
            ]
            for rule, triggered, explanation in checks:
                if triggered and rule not in active[key]:
                    emit(rule, 'medium', event, list(queue), explanation)
                    active[key].add(rule)
        else:
            same_account = [e for e in queue if e.user == event.user]
            if len(same_account) >= config.failure_threshold:
                emit('SSH_SUCCESS_AFTER_FAILURES', 'high', event, same_account + [event],
                     'Successful authentication follows repeated failures for the same account, host and source IP. Investigate; compromise is not proven.')
                # Consume this account's failures to avoid re-alerting on every success.
                history[key] = deque(e for e in queue if e.user != event.user)
            if event.user == 'root':
                emit('SSH_ROOT_LOGIN', 'medium', event, [event],
                     'Successful direct root SSH login. Review whether this is authorized.')
    return alerts
