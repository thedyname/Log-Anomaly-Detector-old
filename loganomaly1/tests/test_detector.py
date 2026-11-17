import csv
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from logdetector.parser import Event, parse_line, read_events
from logdetector.detector import Config, detect
from logdetector.report import render_html, write_reports
BASE=datetime(2026,11,17,10,tzinfo=timezone.utc)
def event(second=0,user='alice',ip='192.0.2.10',host='lab',action='failed',line=1):
    return Event(BASE+timedelta(seconds=second),host,user,ip,action,'password',line)
def burst(): return [event(i,line=i+1) for i in range(5)]
def rules(events): return [a['rule'] for a in detect(events)]
class ParserTests(unittest.TestCase):
    def test_iso_timezone_ipv6(self):
        e=parse_line('2026-11-17T11:00:00+01:00 lab sshd[22]: Failed password for invalid user bob from 2001:db8::1 port 50000 ssh2',7)
        self.assertEqual(e.timestamp,BASE)
        self.assertEqual((e.ip,e.user,e.line),('2001:db8::1','bob',7))
    def test_syslog_year(self):
        line='Nov 17 10:00:00 lab sshd[22]: Accepted publickey for alice from 192.0.2.1 port 22 ssh2: RSA SHA256:abc'
        self.assertIsNone(parse_line(line,1))
        self.assertEqual(parse_line(line,1,2026).timestamp,BASE)
    def test_json(self):
        data={'timestamp':'2026-11-17T10:00:00Z','full_log':'Nov 17 10:00:00 lab sshd[2]: Failed password for alice from 192.0.2.1 port 22 ssh2'}
        self.assertEqual(parse_line(json.dumps(data),1).timestamp,BASE)
    def test_invalid_inputs(self):
        for line in ['{broken','{}','hello','2026-13-17T10:00:00Z lab sshd: Failed password for a from 192.0.2.1 port 22','2026-11-17T10:00:00Z lab sshd: Failed password for a from 999.2.3.4 port 22','2026-11-17T10:00:00Z lab sshd: Failed password for a from 192.0.2.1 port 99999']:
            with self.subTest(line=line): self.assertIsNone(parse_line(line,1))
    def test_only_sshd(self):
        self.assertIsNone(parse_line('2026-11-17T10:00:00Z lab app: Failed password for a from 192.0.2.1 port 22',1))
    def test_counts_order(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input'
            p.write_text('noise\n2026-11-17T10:00:02Z lab sshd: Failed password for a from 192.0.2.1 port 22\n2026-11-17T10:00:01Z lab sshd: Failed password for a from 192.0.2.1 port 22\n')
            events,s=read_events(p)
            self.assertEqual([e.line for e in events],[3,2])
            self.assertEqual(s,{'total_lines':3,'parsed_events':2,'ignored_lines':1})
class DetectionTests(unittest.TestCase):
    def test_burst(self): self.assertEqual(rules(burst()),['SSH_FAILURE_BURST'])
    def test_below(self): self.assertEqual(rules(burst()[:4]),[])
    def test_expired(self): self.assertEqual(rules([event(i*301) for i in range(5)]),[])
    def test_boundary(self):
        self.assertEqual(rules([event(i) for i in [0,1,2,3,300]]),['SSH_FAILURE_BURST'])
        self.assertEqual(rules([event(i) for i in [0,1,2,3,301]]),[])
    def test_accounts(self): self.assertEqual(rules([event(i,user=f'user{i}') for i in range(4)]),['SSH_MULTI_ACCOUNT'])
    def test_separation(self):
        self.assertEqual(rules([event(i,host=str(i)) for i in range(5)]),[])
        self.assertEqual(rules([event(i,ip=f'192.0.2.{i}') for i in range(5)]),[])
    def test_success(self):
        a=detect(burst()+[event(7,action='accepted',line=6)])[-1]
        self.assertEqual(a['rule'],'SSH_SUCCESS_AFTER_FAILURES')
        self.assertEqual(a['evidence_lines'],[1,2,3,4,5,6])
        self.assertEqual(a['failure_count'],5)
    def test_other_account(self): self.assertNotIn('SSH_SUCCESS_AFTER_FAILURES',rules(burst()+[event(7,user='bob',action='accepted')]))
    def test_stale_success(self): self.assertNotIn('SSH_SUCCESS_AFTER_FAILURES',rules(burst()+[event(400,action='accepted')]))
    def test_root(self): self.assertEqual(rules([event(user='root',action='accepted')]),['SSH_ROOT_LOGIN'])
    def test_suppression(self): self.assertEqual(rules([event(i) for i in range(20)]),['SSH_FAILURE_BURST'])
    def test_retrigger(self): self.assertEqual(rules(burst()+[event(400+i) for i in range(5)]),['SSH_FAILURE_BURST']*2)
    def test_consume(self): self.assertEqual(rules(burst()+[event(7,action='accepted'),event(8,action='accepted')]).count('SSH_SUCCESS_AFTER_FAILURES'),1)
    def test_sort(self): self.assertEqual(detect(burst()),detect(list(reversed(burst()))))
    def test_config(self):
        for args in [(0,5,4),(300,1,4),(300,5,1)]:
            with self.assertRaises(ValueError): Config(*args)
class ReportTests(unittest.TestCase):
    def result(self): return {'summary':{'parsed_events':1,'ignored_lines':0},'alerts':detect([event(user='root',host='<script>alert(1)</script>',action='accepted')])}
    def test_escape(self):
        page=render_html(self.result())
        self.assertNotIn('<script>alert(1)</script>',page)
        self.assertIn('&lt;script&gt;',page)
    def test_exports(self):
        r=self.result();r['alerts'][0]['user']='=HYPERLINK("evil")'
        with tempfile.TemporaryDirectory() as d:
            write_reports(d,r)
            self.assertEqual(json.loads((Path(d)/'alerts.json').read_text()),r)
            with (Path(d)/'alerts.csv').open() as f: self.assertTrue(next(csv.DictReader(f))['user'].startswith("'="))
    def test_empty(self): self.assertIn('No detection thresholds',render_html({'summary':{'parsed_events':1,'ignored_lines':0},'alerts':[]}))
    def test_cli_demo(self):
        with tempfile.TemporaryDirectory() as d:
            cmd=[sys.executable,'-m','logdetector','samples/ssh_demo.log','--output',d]
            p=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(len(json.loads((Path(d)/'alerts.json').read_text())['alerts']),4)
            self.assertEqual(subprocess.run(cmd+['--fail-on-alert'],capture_output=True).returncode,1)
    def test_cli_error(self):
        p=subprocess.run([sys.executable,'-m','logdetector','missing-file'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2)
        self.assertNotIn('Traceback',p.stderr)
if __name__=='__main__': unittest.main()
