"""Inspect an offline Burp export; --apply imports only the selected email's SSO."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    from core.grok_capture import inspect_capture, import_capture, CaptureError
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', required=True, type=Path)
    parser.add_argument('--email', required=True)
    parser.add_argument('--apply', action='store_true', help='Save SSO only; never passwords or network requests')
    args = parser.parse_args()
    try:
        record = inspect_capture(args.file, args.email)
        result = {'ok': True, 'capture_session_verified': record.capture_session_verified,
                  'live_session_verified': False, 'registration_origin': 'manual_capture',
                  'password_imported': False, 'source_sha256': record.source_sha256}
        if args.apply: result.update(import_capture(args.file, args.email))
        else: result.update(dry_run=True, has_sso=bool(record.sso), has_sso_rw=bool(record.sso_rw))
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except CaptureError as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
    except (OSError, ValueError, TypeError):
        print(json.dumps({'ok': False, 'error': '无法读取或解析指定抓包；未记录路径以外的敏感内容'}, ensure_ascii=False))
    return 1


if __name__ == '__main__': raise SystemExit(main())
