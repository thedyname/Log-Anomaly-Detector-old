"""CLI entry point: python3 -m logdetector --help."""
import argparse
import sys
from dataclasses import asdict
from pathlib import Path
from .detector import Config, detect
from .parser import read_events
from .report import write_reports


def main(argv=None):
    parser = argparse.ArgumentParser(description='Analyze offline OpenSSH logs and Wazuh JSONL full_log records.')
    parser.add_argument('input', type=Path, help='UTF-8 log file (one event per line)')
    parser.add_argument('--output', type=Path, default=Path('reports'), help='Report directory (default: reports)')
    parser.add_argument('--year', type=int, help='Explicit year for traditional syslog timestamps')
    parser.add_argument('--window', type=int, default=300, help='Inclusive sliding window in seconds')
    parser.add_argument('--threshold', type=int, default=5, help='Failed authentication threshold')
    parser.add_argument('--users', type=int, default=4, help='Distinct failed accounts threshold')
    parser.add_argument('--fail-on-alert', action='store_true', help='Exit 1 when alerts are detected (for automation)')
    args = parser.parse_args(argv)
    try:
        config = Config(args.window, args.threshold, args.users)
        if args.year is not None and not 1 <= args.year <= 9999:
            raise ValueError('--year must be between 1 and 9999')
        # Prevent accidental destruction of an input placed inside the output directory.
        if args.input.resolve() in {(args.output / name).resolve() for name in ['alerts.json','alerts.csv','dashboard.html']}:
            raise ValueError('Input path overlaps a generated report')
        events, summary = read_events(args.input, args.year)
        if not events:
            raise ValueError('No supported SSH events parsed. Check format and supply --year for traditional syslog.')
        alerts = detect(events, config)
        result = {'schema_version': 1, 'config': asdict(config), 'summary': summary, 'alerts': alerts}
        write_reports(args.output, result)
    except (OSError, ValueError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2
    print(f"Parsed {summary['parsed_events']} events; ignored {summary['ignored_lines']} lines; generated {len(alerts)} alerts.")
    print(f'Dashboard: {args.output / "dashboard.html"}')
    return 1 if args.fail_on_alert and alerts else 0

if __name__ == '__main__':
    raise SystemExit(main())
