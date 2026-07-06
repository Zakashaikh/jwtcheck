"""
test_cli.py — end-to-end CLI tests for both subcommands.

Drives jwtcheck.cli.main() directly with argument lists and captures stdout.
"""

import base64
import hashlib
import hmac
import json

import pytest

from jwtcheck.cli import main


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hs256_token(secret: str, payload: dict) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode()
    sig = _b64(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------

def test_scan_vulnerable_file_exits_1(tmp_path, capsys):
    f = tmp_path / "vuln.py"
    f.write_text('import jwt\njwt.decode(t, k, algorithms=["none"])\n', encoding="utf-8")
    rc = main(["scan", str(f)])
    out = capsys.readouterr().out
    assert rc == 1                 # findings present -> CI failure
    assert "R02" in out            # none algorithm


def test_scan_clean_file_exits_0(tmp_path, capsys):
    f = tmp_path / "clean.py"
    f.write_text(
        'import jwt\n'
        'try:\n'
        '    jwt.decode(t, k, algorithms=["HS256"], audience="a", issuer="i")\n'
        'except jwt.PyJWTError:\n'
        '    pass\n',
        encoding="utf-8",
    )
    rc = main(["scan", str(f)])
    # Only MEDIUM/LOW possible here (no CRITICAL/HIGH) -> exit 0
    assert rc == 0


def test_scan_sarif_format(tmp_path, capsys):
    f = tmp_path / "vuln.py"
    f.write_text('import jwt\njwt.decode(t, k, algorithms=["none"])\n', encoding="utf-8")
    main(["scan", str(f), "--format", "sarif"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"


def test_scan_output_file_strips_ansi(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text('import jwt\njwt.decode(t, k, algorithms=["none"])\n', encoding="utf-8")
    out_file = tmp_path / "report.txt"
    main(["scan", str(f), "-o", str(out_file)])
    content = out_file.read_text(encoding="utf-8")
    assert "\033[" not in content        # no ANSI escapes in file output
    assert "R02" in content


def test_scan_missing_target_exits_2(capsys):
    rc = main(["scan", "does_not_exist_12345.py"])
    assert rc == 2


def test_scan_exclude_tests_skips_test_files(tmp_path, capsys):
    # A vulnerable file inside a tests/ directory.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_vuln.py").write_text(
        'import jwt\njwt.decode(t, k, algorithms=["none"])\n', encoding="utf-8"
    )
    # A vulnerable file in production source.
    (tmp_path / "app.py").write_text(
        'import jwt\njwt.decode(t, k, algorithms=["none"])\n', encoding="utf-8"
    )

    # Without exclusion: both files flagged.
    main(["scan", str(tmp_path), "--recursive"])
    full = capsys.readouterr().out
    assert "test_vuln.py" in full and "app.py" in full

    # With exclusion: only the production file remains.
    main(["scan", str(tmp_path), "--recursive", "--exclude-tests"])
    filtered = capsys.readouterr().out
    assert "test_vuln.py" not in filtered
    assert "app.py" in filtered


# ---------------------------------------------------------------------------
# analyse subcommand
# ---------------------------------------------------------------------------

def test_analyse_file(tmp_path, capsys):
    token = _hs256_token("secret", {"sub": "u", "exp": 1})
    f = tmp_path / "tokens.log"
    f.write_text(f"auth header: {token}\n", encoding="utf-8")
    rc = main(["analyse", str(f), "--log"])
    out = capsys.readouterr().out
    assert "HS256" in out
    assert "EXPIRED" in out
    assert rc == 1                       # expired/HIGH -> exit 1


def test_analyse_with_wordlist_cracks_secret(tmp_path, capsys):
    token = _hs256_token("secret", {"sub": "u", "exp": 9999999999})
    f = tmp_path / "tok.txt"
    f.write_text(token, encoding="utf-8")
    wl = tmp_path / "wl.txt"
    wl.write_text("wrong\nsecret\n", encoding="utf-8")
    rc = main(["analyse", str(f), "--bruteforce", "--wordlist", str(wl)])
    out = capsys.readouterr().out
    assert "CRACKED" in out
    assert "secret" in out
    assert rc == 1


def test_analyse_no_tokens_found(tmp_path, capsys):
    f = tmp_path / "empty.log"
    f.write_text("nothing to see here\n", encoding="utf-8")
    rc = main(["analyse", str(f)])
    out = capsys.readouterr().out
    assert "No JWT tokens found" in out
    assert rc == 0
