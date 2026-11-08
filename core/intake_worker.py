"""Subprocess boundary for untrusted compressed data; password stays in the environment."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.evidence import write_json
from core.intake import extract_member


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--options', required=True)
    parser.add_argument('--member')
    args = parser.parse_args()
    try:
        cfg = json.loads(Path(args.options).read_text())
        path, metadata = extract_member(args.input, args.member, args.output, cfg,
                                        os.environ.get(cfg['password_env']))
        write_json(Path(args.output) / 'result.json', {'status': 'completed', 'path': str(path), **metadata})
    except Exception as exc:
        write_json(Path(args.output) / 'result.json', {'status': 'failed', 'error': f'{type(exc).__name__}: {exc}'})
        raise SystemExit(1)
