"""
cli.py — Command-line entry point for JWTCheck.

Two subcommands:
    jwtcheck scan <target>      static analysis of Python source for PyJWT misuse
    jwtcheck analyse [target]   decode and assess raw JWT tokens

Exit codes:
    0  success, no findings
    1  findings present
    2  error (bad path, unreadable input, etc.)
"""

import argparse
import json
import os
import sys
from typing import List

from . import __version__
from .analyser import Analyser
from .bruteforce import crack
from .reporter import (
    render_sarif,
    render_text,
    render_token_report_text,
)
from .scanner import Finding, Scanner
from .utils import extract_tokens_from_text, strip_ansi

_HMAC_ALGS = {"HS256", "HS384", "HS512"}

# Severity ranking for the --severity threshold filter (lower index = worse).
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEVERITY_THRESHOLDS = {"critical": 0, "high": 1, "medium": 2, "all": 99}


def _write_output(text: str, output_path: str) -> None:
    """Write text to a file (ANSI stripped) or to stdout."""
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(strip_ansi(text) + "\n")
    else:
        print(text)


def _filter_by_severity(findings: List[Finding], level: str) -> List[Finding]:
    """Keep findings at or above the requested severity threshold."""
    threshold = _SEVERITY_THRESHOLDS.get(level, 99)
    return [f for f in findings if _SEVERITY_RANK.get(f.severity, 99) <= threshold]


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------

def _run_scan(args: argparse.Namespace) -> int:
    scanner = Scanner()
    if os.path.isdir(args.target):
        findings: List[Finding] = scanner.scan_directory(
            args.target,
            recursive=args.recursive,
            exclude_tests=args.exclude_tests,
        )
    elif os.path.isfile(args.target):
        findings = scanner.scan_file(args.target)
    else:
        print(f"Error: target not found: {args.target}", file=sys.stderr)
        return 2

    findings = _filter_by_severity(findings, args.severity)

    if args.format == "sarif":
        output = render_sarif(findings, tool_version=__version__)
    else:
        output = render_text(findings, show_remediation=not args.no_remediation)

    _write_output(output, args.output)

    # Exit 1 if any findings remain after filtering, else 0.
    return 1 if findings else 0


# ---------------------------------------------------------------------------
# analyse subcommand
# ---------------------------------------------------------------------------

def _gather_tokens(args: argparse.Namespace) -> List[str]:
    """Collect candidate tokens from stdin, a token file, or a log file."""
    if args.stdin:
        text = sys.stdin.read()
    elif args.target:
        with open(args.target, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        raise ValueError("provide a target file or --stdin")

    if args.log:
        # Log file: regex-extract embedded tokens from arbitrary text.
        return extract_tokens_from_text(text)

    # Token source: one token per line. Strip whitespace and any surrounding
    # quotes (common when a token is pasted via `echo "..."` on Windows cmd,
    # which keeps the quotes). Fall back to regex extraction if the cleaned
    # lines do not look like raw JWTs (e.g. a token embedded in other text).
    lines = [_strip_wrappers(ln) for ln in text.splitlines() if ln.strip()]
    line_tokens = [ln for ln in lines if ln.count(".") == 2]
    return line_tokens or extract_tokens_from_text(text)


def _strip_wrappers(raw: str) -> str:
    """Strip surrounding whitespace and a single layer of matching quotes."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    return s


def _run_analyse(args: argparse.Namespace) -> int:
    try:
        tokens = _gather_tokens(args)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not tokens:
        print("No JWT tokens found in input.")
        return 0

    analyser = Analyser()
    reports = []
    worst_exit = 0

    for token in tokens:
        report = analyser.analyse(token)

        # Brute-force only when explicitly requested, with a wordlist, on HMAC.
        if (
            args.bruteforce
            and args.wordlist
            and report.algorithm in _HMAC_ALGS
            and not report.error
        ):
            try:
                report.cracked_secret = crack(
                    token, args.wordlist, timeout=args.timeout
                )
            except (ValueError, OSError):
                report.cracked_secret = None

        reports.append(report)
        if report.summary_severity() in ("CRITICAL", "HIGH") or report.cracked_secret:
            worst_exit = 1

    if args.format == "json":
        import dataclasses
        payload = [dataclasses.asdict(r) for r in reports]
        output = json.dumps(payload, indent=2, default=str)
    else:
        blocks = [
            f"=== Token {i} of {len(reports)} ===\n" + render_token_report_text(r)
            for i, r in enumerate(reports, start=1)
        ]
        output = "\n\n".join(blocks)

    _write_output(output, getattr(args, "output", "") or "")
    return worst_exit


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwtcheck",
        description="JWT cryptographic misuse detector (static analysis + token assessment).",
    )
    parser.add_argument("--version", action="version", version=f"jwtcheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Static analysis of Python source for PyJWT misuse.")
    p_scan.add_argument("target", help="File or directory to scan.")
    p_scan.add_argument("--recursive", "-r", action="store_true",
                        help="Recurse into subdirectories.")
    p_scan.add_argument("--format", choices=["text", "sarif"], default="text",
                        help="Output format (default: text).")
    p_scan.add_argument("--output", "-o", default="",
                        help="Write to file instead of stdout (ANSI stripped).")
    p_scan.add_argument("--severity", choices=["critical", "high", "medium", "all"],
                        default="all",
                        help="Only report findings at or above this severity (default: all).")
    p_scan.add_argument("--exclude-tests", action="store_true",
                        help="Skip test/fixture files (test_*.py, tests/ dirs, conftest.py).")
    p_scan.add_argument("--no-remediation", action="store_true",
                        help="Suppress remediation text.")
    p_scan.set_defaults(func=_run_scan)

    # analyse (accept the American spelling "analyze" as an alias)
    p_an = sub.add_parser("analyse", aliases=["analyze"],
                          help="Decode and assess raw JWT tokens.")
    p_an.add_argument("target", nargs="?", default="",
                      help="Token file (one per line) or log file (with --log).")
    p_an.add_argument("--stdin", action="store_true", help="Read input from stdin.")
    p_an.add_argument("--log", action="store_true",
                      help="Treat input as a log file and regex-extract embedded tokens.")
    p_an.add_argument("--bruteforce", action="store_true",
                      help="Attempt HMAC secret recovery (requires --wordlist).")
    p_an.add_argument("--wordlist", "-w", default="",
                      help="Wordlist path for HMAC secret brute-forcing.")
    p_an.add_argument("--timeout", type=int, default=30,
                      help="Brute-force timeout in seconds (default: 30).")
    p_an.add_argument("--format", choices=["text", "json"], default="text",
                      help="Output format (default: text).")
    p_an.add_argument("--output", "-o", default="",
                      help="Write to file instead of stdout (ANSI stripped).")
    p_an.set_defaults(func=_run_analyse)

    return parser


def main(argv: List[str] = None) -> int:
    # Ensure non-ASCII output (em dashes, check marks) survives on Windows
    # consoles that default to a legacy code page such as cp1252.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
