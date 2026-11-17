"""Portable reports: HTML is escaped and loads no external dependencies."""
import csv
import html
import json
from collections import Counter
from pathlib import Path

FIELDS = ['id', 'rule', 'severity', 'timestamp', 'host', 'source_ip', 'user', 'failure_count', 'users', 'evidence_lines', 'explanation']


def safe_cell(value):
    text = str(value)
    # Prevent spreadsheet formula interpretation when exporting untrusted logs.
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def write_reports(output, result):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'alerts.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    with (output / 'alerts.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for alert in result['alerts']:
            writer.writerow({k: safe_cell('; '.join(map(str, v)) if isinstance(v, list) else v) for k, v in alert.items()})
    (output / 'dashboard.html').write_text(render_html(result), encoding='utf-8')


def render_html(result):
    esc = lambda value: html.escape(str(value), quote=True)
    alerts = result['alerts']
    summary = result['summary']
    counts = Counter(a['rule'] for a in alerts)
    bars = ''.join(f'<div class="barrow"><span>{esc(rule)}</span><meter min="0" max="{max(counts.values(), default=1)}" value="{count}"></meter><b>{count}</b></div>' for rule, count in counts.items())
    rows = ''.join('<tr data-severity="'+esc(a['severity'])+'">' +
                   ''.join('<td>'+esc(a[k])+'</td>' for k in ['id','severity','rule','timestamp','host','source_ip','user','failure_count']) +
                   '<td>'+esc(', '.join(map(str,a['evidence_lines'])))+'</td><td>'+esc(a['explanation'])+'</td></tr>' for a in alerts)
    cards = ''.join(f'<article><span>{label}</span><strong>{value}</strong></article>' for label, value in [
        ('Parsed events', summary['parsed_events']), ('Ignored lines', summary['ignored_lines']),
        ('Alerts', len(alerts)), ('High severity', sum(a['severity']=='high' for a in alerts))])
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Anomaly Detector — SOC report</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1220;color:#e6edf7}body{max-width:1440px;margin:auto;padding:40px 24px}header{border-bottom:1px solid #27354c;padding-bottom:24px}.eyebrow{color:#45d5c2;letter-spacing:.18em;font-size:12px}h1{font-size:clamp(28px,4vw,44px);margin:12px 0}p{color:#aab9d0;line-height:1.6}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:28px 0}article,.panel{background:#121e31;border:1px solid #27354c;border-radius:12px;padding:22px}article span{display:block;color:#aab9d0}strong{display:block;font-size:40px;margin-top:10px}.panel{margin:20px 0}.barrow{display:flex;gap:20px;align-items:center;margin:16px 0}.barrow span{width:260px;font-size:13px}meter{flex:1;height:18px}input,select{background:#0b1220;color:#e6edf7;border:1px solid #425574;border-radius:6px;padding:12px;margin:4px}input{width:min(380px,80%)}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:14px 12px;border-bottom:1px solid #27354c;vertical-align:top}th{color:#45d5c2;white-space:nowrap}tr[data-severity=high] td:nth-child(2){color:#ff987e;font-weight:bold}footer{margin-top:28px;color:#aab9d0;font-size:13px}@media(max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}body{padding:20px 12px}.barrow span{width:150px;font-size:11px}}
</style></head><body><header><div class="eyebrow">SOC LAB / OFFLINE ANALYSIS</div><h1>Log Anomaly Detector</h1><p>Explainable SSH detections · Evidence you can inspect · Local analysis</p></header>
<div class="cards">'''+cards+'''</div><section class="panel"><h2>Detection overview</h2>'''+(bars or '<p>No detection thresholds were reached.</p>')+'''</section><section class="panel"><h2>Alert investigation</h2><label for="query">Search </label><input id="query" placeholder="IP address, host, account or rule"><label for="severity">Severity </label><select id="severity"><option value="">All</option><option value="high">High</option><option value="medium">Medium</option></select><p id="visible" aria-live="polite"></p><div class="scroll"><table><thead><tr>'''+''.join('<th>'+x+'</th>' for x in ['ID','Severity','Rule','Time (UTC)','Host','Source IP','Account','Failures','Input lines','Explanation'])+'''</tr></thead><tbody>'''+rows+'''</tbody></table></div></section><footer>Rule-based learning project. An alert is a lead for investigation, not proof of an attack. Timestamps without an offset are interpreted as UTC. Ignored lines may include unsupported or malformed events.</footer><script>
const query=document.getElementById('query'),severity=document.getElementById('severity');
function filter(){let n=0;document.querySelectorAll('tbody tr').forEach(row=>{const show=row.textContent.toLowerCase().includes(query.value.toLowerCase())&&(!severity.value||row.dataset.severity===severity.value);row.hidden=!show;if(show)n++;});document.getElementById('visible').textContent=n+' alert(s) displayed';}
query.addEventListener('input',filter);severity.addEventListener('change',filter);filter();
</script></body></html>'''
