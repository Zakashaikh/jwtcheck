"""
scanner.py — AST-based static analysis engine for PyJWT misuse detection.

Core dissertation contribution: adapts 15 detection rules from the JWTKey
framework (Xu et al., ESORICS 2023) to Python/PyJWT via Python's ``ast`` module.

Architecture
------------
JWTVisitor  — walks the AST and fires rules on matching call sites.
              * Tracks ``import jwt`` aliases so only genuine PyJWT calls match
                (``jwt.decode``, ``j.decode``, ``from jwt import decode``), which
                avoids false positives on ``bytes.decode()`` / ``str.encode()``.
              * Tracks variable assignments so ``payload = {...}; jwt.encode(payload)``
                and ``secret = "..."; jwt.decode(t, secret)`` resolve correctly —
                required by R05–R07, R10 and R14.
Scanner     — public interface; handles file and directory scanning.
Finding     — dataclass representing one rule violation.

Design note (deviation from the original brief)
------------------------------------------------
The brief proposed matching call sites on the attribute name alone (``.decode``).
That is replaced here with import-alias tracking, because the attribute-only
approach misclassifies ``bytes.decode()`` / ``str.encode()`` as PyJWT calls,
producing spurious CRITICAL findings on ordinary code that never touches JWTs.

The brief also defined R15 in terms of whether a decode call was wrapped in
error handling, to be detected by scanning the 10 raw source lines above the
call for ``try:``. That definition was abandoned: the text scan is defeated by
comments, string literals and nested scopes, and — more fundamentally — the
presence of a ``try`` block says nothing about cryptographic correctness. R15
was redefined to detect a genuine misuse instead: a verification key loaded
from ``os.environ`` while the algorithms list is left unpinned, which is the
precondition for an algorithm-confusion attack (CVE-2022-29217).
"""

import ast
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from .rules import get_rule


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One rule violation detected during scanning."""
    rule_id: str
    rule_name: str
    severity: str
    description: str
    remediation: str
    filepath: str
    line: int
    col: int
    snippet: str            # the source line where the violation occurs
    cwe: Optional[str] = None


# ---------------------------------------------------------------------------
# AST Visitor
# ---------------------------------------------------------------------------

class JWTVisitor(ast.NodeVisitor):
    """Walks a Python AST and fires detection rules against PyJWT call sites."""

    def __init__(self, source_lines: List[str], filepath: str) -> None:
        self.findings: List[Finding] = []
        self._source_lines = source_lines
        self._filepath = filepath

        # name -> AST node of the assigned value (flat scope, per the brief)
        self._assignments: Dict[str, ast.AST] = {}

        # Names bound to the ``jwt`` package, e.g. {'jwt', 'j'}
        self._jwt_aliases: Set[str] = set()
        # Directly-imported jwt members: local name -> original name
        # e.g. {'decode': 'decode', 'd': 'decode', 'PyJWKClient': 'PyJWKClient'}
        self._jwt_funcs: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Reporting helper
    # ------------------------------------------------------------------

    def _report(self, rule_id: str, node: ast.AST) -> None:
        """Create a Finding for the given rule and append it to self.findings."""
        rule = get_rule(rule_id)
        if rule is None:
            return
        line = getattr(node, 'lineno', 0)
        col = getattr(node, 'col_offset', 0)
        snippet = ""
        if 0 < line <= len(self._source_lines):
            snippet = self._source_lines[line - 1].strip()
        self.findings.append(Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            description=rule.description,
            remediation=rule.remediation,
            filepath=self._filepath,
            line=line,
            col=col,
            snippet=snippet,
            cwe=rule.cwe,
        ))

    # ------------------------------------------------------------------
    # Import tracking
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        """Record aliases bound to the jwt package (``import jwt [as j]``)."""
        for alias in node.names:
            top = alias.name.split('.')[0]
            if top == 'jwt':
                self._jwt_aliases.add(alias.asname or top)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record members imported directly from jwt (``from jwt import decode``).

        ``node.level`` must be 0. A relative import such as ``from ..jwt import
        decode`` also reports ``module == 'jwt'``, but binds a *local* jwt.py,
        not PyJWT. Held-out validation caught this on arXiv/arxiv-auth, where
        the local wrapper pins the algorithm internally and every call to it was
        being analysed as a bare PyJWT decode.
        """
        if node.level == 0 and node.module and node.module.split('.')[0] == 'jwt':
            for alias in node.names:
                local = alias.asname or alias.name
                self._jwt_funcs[local] = alias.name
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Call classification (alias-aware)
    # ------------------------------------------------------------------

    def _jwt_method(self, node: ast.Call) -> Optional[str]:
        """
        Return 'decode' or 'encode' if this call is a genuine PyJWT call.

        Matches ``<jwt_alias>.decode(...)`` and ``decode(...)`` where ``decode``
        was imported from jwt. Returns None otherwise.
        """
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in self._jwt_aliases
            and func.attr in ('decode', 'encode')
        ):
            return func.attr
        if isinstance(func, ast.Name) and func.id in self._jwt_funcs:
            original = self._jwt_funcs[func.id]
            if original in ('decode', 'encode'):
                return original
        return None

    # ------------------------------------------------------------------
    # AST-value helpers
    # ------------------------------------------------------------------

    def _get_keyword_value(self, call: ast.Call, name: str) -> Optional[ast.AST]:
        """Return the AST node for keyword argument ``name``, or None if absent."""
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _get_arg(self, call: ast.Call, name: str,
                 position: Optional[int] = None) -> Optional[ast.AST]:
        """
        Return an argument supplied by keyword OR by position.

        PyJWT's decode() accepts algorithms and options positionally —
        ``jwt.decode(token, key, ['HS256'])`` pins the algorithm at position 2
        with no ``algorithms=`` keyword. Matching the keyword alone misses this
        form and produces false positives (notably R01). When the keyword is
        absent, fall back to the positional argument at ``position``.
        """
        kw = self._get_keyword_value(call, name)
        if kw is not None:
            return kw
        if position is not None and len(call.args) > position:
            return call.args[position]
        return None

    def _resolve(self, node: Optional[ast.AST]) -> Optional[ast.AST]:
        """Resolve a Name to its last assigned value; otherwise return as-is."""
        if isinstance(node, ast.Name):
            return self._assignments.get(node.id, node)
        return node

    def _is_string_literal(self, node: Optional[ast.AST]) -> bool:
        """Return True if node is a string constant."""
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def _get_algorithms_list(self, node: ast.Call) -> Optional[List[str]]:
        """
        Extract the algorithm names from ``algorithms=``.

        Handles a list literal (``["HS256", "none"]``), a single string literal
        (``"HS256"``), and a Name that resolves to either. Returns None when the
        argument is absent or its value cannot be resolved statically.
        """
        kw_val = self._resolve(self._get_arg(node, 'algorithms', 2))
        if kw_val is None:
            return None
        if isinstance(kw_val, ast.Constant) and isinstance(kw_val.value, str):
            return [kw_val.value]
        if isinstance(kw_val, ast.List):
            result: List[str] = []
            for elt in kw_val.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    result.append(elt.value)
            return result
        return None  # dynamic / unresolvable value

    def _get_options_dict(self, node: ast.Call) -> Optional[Dict[str, Any]]:
        """
        Extract ``options={...}`` as a plain dict of string keys -> bool values.

        Returns None if options= is absent or not a dict literal.
        """
        kw_val = self._resolve(self._get_arg(node, 'options', 3))
        if not isinstance(kw_val, ast.Dict):
            return None
        result: Dict[str, Any] = {}
        for k, v in zip(kw_val.keys, kw_val.values):
            if (
                isinstance(k, ast.Constant) and isinstance(k.value, str)
                and isinstance(v, ast.Constant) and isinstance(v.value, bool)
            ):
                result[k.value] = v.value
        return result

    def _is_env_var_load(self, node: Optional[ast.AST]) -> bool:
        """Return True if node is ``os.environ.get(...)`` or ``os.environ[...]``."""
        # os.environ.get("KEY")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'get'
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == 'environ'
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == 'os'
        ):
            return True
        # os.environ["KEY"]
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == 'environ'
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == 'os'
        ):
            return True
        return False

    def _payload_has_exp(self, node: Optional[ast.AST]) -> bool:
        """
        Return True if the payload dict literal contains an 'exp' key.

        Conservatively returns True for non-literal payloads (and for dicts that
        use ``**unpacking``) since their contents cannot be determined statically;
        this avoids false-positive R06 findings.
        """
        resolved = self._resolve(node)
        if not isinstance(resolved, ast.Dict):
            return True
        for key in resolved.keys:
            if key is None:
                return True  # dict unpacking — cannot tell statically
            if isinstance(key, ast.Constant) and key.value == 'exp':
                return True
        return False

    # ------------------------------------------------------------------
    # Assignment tracking
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track simple ``name = value`` assignments for later resolution."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._assignments[target.id] = node.value
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Call dispatch
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        method = self._jwt_method(node)
        if method == 'decode':
            self._check_decode_call(node)
        elif method == 'encode':
            self._check_encode_call(node)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Rule checkers
    # ------------------------------------------------------------------

    def _decode_key_node(self, node: ast.Call) -> Optional[ast.AST]:
        """Return the key argument of a decode call (2nd positional or key=)."""
        if len(node.args) > 1:
            return node.args[1]
        return self._get_keyword_value(node, 'key')

    def _check_decode_call(self, node: ast.Call) -> None:
        """Rules for jwt.decode(): R01, R02, R03, R04, R06, R08, R09, R11–R15."""
        algorithms_present = self._get_arg(node, 'algorithms', 2) is not None
        algorithms = self._get_algorithms_list(node)
        options = self._get_options_dict(node) or {}
        key_node = self._decode_key_node(node)
        resolved_key = self._resolve(key_node)

        has_none = bool(algorithms) and any(a.lower() == 'none' for a in algorithms)

        # Signature verification explicitly disabled — via the options dict
        # (options={"verify_signature": False}) or the deprecated verify=False
        # keyword. When verification is off, the token is not trusted, so the
        # claim/algorithm rules (R01, R08, R09) are moot: raising them alongside
        # R03 just produces redundant noise on legitimate token-inspection code.
        # We therefore surface the single meaningful signal (R03) and suppress
        # the rest. This was informed by the real-world study, where every
        # false positive came from intentional unverified decoding.
        verify_kw = self._resolve(self._get_keyword_value(node, 'verify'))
        verify_disabled = (
            options.get('verify_signature') is False
            or (isinstance(verify_kw, ast.Constant) and verify_kw.value is False)
        )

        # R01 — no algorithms parameter at all
        if not algorithms_present and not verify_disabled:
            self._report('R01', node)

        # R02 — "none" algorithm accepted
        if has_none:
            self._report('R02', node)

        # R03 / R11 / R13 — verification disabled via options dict
        if verify_disabled:
            self._report('R03', node)
        if options.get('verify_iss') is False:
            self._report('R11', node)
        if options.get('verify_exp') is False:
            self._report('R13', node)

        # R04 — HMAC and asymmetric algorithms mixed (algorithm confusion)
        if algorithms:
            has_hmac = any(a.upper().startswith('HS') for a in algorithms)
            has_asym = any(
                a.upper().startswith(('RS', 'ES', 'PS')) for a in algorithms
            )
            if has_hmac and has_asym:
                self._report('R04', node)

        # R14 — PEM key material inlined as a string literal.
        is_pem_literal = (
            isinstance(resolved_key, ast.Constant)
            and isinstance(resolved_key.value, str)
            and resolved_key.value.lstrip().startswith('-----BEGIN')
        )
        if is_pem_literal:
            self._report('R14', node)

        # R06 — hardcoded string-literal verification key.
        #
        # Suppressed when the literal is PEM key material, for two reasons.
        # R14 already reports that case with the correct framing, so raising
        # both duplicates one weakness. More importantly, a decode key is
        # normally the *public* half of an asymmetric pair, and a public key
        # inlined in source is not a hardcoded secret — calling it one is a
        # false positive. R06 is for a shared secret appearing in the source.
        if self._is_string_literal(resolved_key) and not is_pem_literal:
            self._report('R06', node)

        # R08 — no audience validation (moot when verification is disabled)
        if not verify_disabled and self._get_keyword_value(node, 'audience') is None:
            self._report('R08', node)

        # R09 — no issuer validation (moot when verification is disabled)
        if not verify_disabled and self._get_keyword_value(node, 'issuer') is None:
            self._report('R09', node)

        # R12 — excessive leeway (> 300 seconds)
        leeway_node = self._resolve(self._get_keyword_value(node, 'leeway'))
        if (
            isinstance(leeway_node, ast.Constant)
            and isinstance(leeway_node.value, (int, float))
            and not isinstance(leeway_node.value, bool)
            and leeway_node.value > 300
        ):
            self._report('R12', node)

        # R15 — env-var secret with algorithms not pinned to a single algorithm
        if self._is_env_var_load(resolved_key) and algorithms is not None and len(algorithms) > 1:
            self._report('R15', node)

    def _check_encode_call(self, node: ast.Call) -> None:
        """Rules for jwt.encode(): R05, R07, R10."""
        payload_node = node.args[0] if len(node.args) > 0 else None
        key_node = node.args[1] if len(node.args) > 1 else self._get_keyword_value(node, 'key')
        resolved_key = self._resolve(key_node)

        # R05 — hardcoded string-literal signing key
        if self._is_string_literal(resolved_key):
            self._report('R05', node)

        # R07 — payload missing an exp claim
        if payload_node is not None and not self._payload_has_exp(payload_node):
            self._report('R07', node)

        # R10 — exp and iat integer literals more than 86400 seconds apart.
        #
        # KNOWN LIMITATION: this matches integer literals only. The idiomatic
        # form — exp: datetime.now(tz) + timedelta(days=30) — is an ast.BinOp
        # and is NOT detected. R10's low real-world frequency is therefore at
        # least partly an artefact of this rule, not solely evidence that long
        # lifetimes are rare. Extending it would change detection behaviour and
        # so invalidate the evaluation figures already reported; it is recorded
        # as future work instead.
        exp = self._get_int_claim(payload_node, 'exp')
        iat = self._get_int_claim(payload_node, 'iat')
        if exp is not None and iat is not None and (exp - iat) > 86400:
            self._report('R10', node)

    def _get_int_claim(self, payload_node: Optional[ast.AST], claim: str) -> Optional[int]:
        """Return an integer-literal claim value from a payload dict, or None."""
        resolved = self._resolve(payload_node)
        if not isinstance(resolved, ast.Dict):
            return None
        for key, val in zip(resolved.keys, resolved.values):
            if (
                isinstance(key, ast.Constant) and key.value == claim
                and isinstance(val, ast.Constant)
                and isinstance(val.value, int)
                and not isinstance(val.value, bool)
            ):
                return val.value
        return None


# ---------------------------------------------------------------------------
# Public Scanner class
# ---------------------------------------------------------------------------

_SKIP_DIRS = frozenset({
    '__pycache__', '.venv', 'venv', 'env', 'node_modules',
    '.git', '.tox', '.mypy_cache', '.pytest_cache', 'dist', 'build',
    # Installed third-party code, never the project's own. Matching on these
    # rather than only on the virtualenv's name is what makes the skip robust:
    # a virtualenv may be called anything (held-out validation found one named
    # myenv/ whose vendored redis package was scanned as if it were the
    # application's source), but the package directory inside it is always
    # site-packages or dist-packages.
    'site-packages', 'dist-packages',
})

# Directory names and filename prefixes that indicate test / fixture code.
# Used by --exclude-tests so a production scan is not dominated by the
# intentionally-insecure tokens that test suites legitimately construct.
_TEST_DIR_NAMES = frozenset({'tests', 'test', 'testing', 'fixtures', 'conftest'})


def _is_test_path(filepath: str) -> bool:
    """Return True if a path looks like test or fixture code."""
    norm = filepath.replace('\\', '/').lower()
    parts = norm.split('/')
    if any(part in _TEST_DIR_NAMES for part in parts[:-1]):
        return True
    name = parts[-1]
    return name.startswith('test_') or name.endswith('_test.py') or name == 'conftest.py'


class Scanner:
    """Public interface for file and directory scanning."""

    def __init__(self) -> None:
        # Files that mentioned 'jwt' but could not be analysed, as
        # (filepath, reason) pairs. An unparseable file previously returned []
        # and was therefore indistinguishable from a genuinely clean one — a
        # silent all-clear, the worst failure mode for a security tool. The
        # real-world study found 5 such files, 2 of them containing real misuse.
        # Accumulates across every scan_file call, so scan_directory keeps the
        # whole list.
        self.skipped: List[tuple] = []

    def scan_file(self, filepath: str) -> List[Finding]:
        """
        Scan a single Python file for JWT misuse patterns.

        Quick pre-filter: if 'jwt' does not appear in the source (case-insensitive)
        the file is skipped without AST parsing. Files that pass that pre-filter
        but cannot be read or parsed are recorded in ``self.skipped``; files
        without 'jwt' are not interesting and are not reported.
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
                source = fh.read()
        except OSError as exc:
            self.skipped.append((filepath, f"could not read file: {exc}"))
            return []

        if 'jwt' not in source.lower():
            return []

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as exc:
            self.skipped.append((filepath, f"syntax error: {exc.msg} (line {exc.lineno})"))
            return []

        visitor = JWTVisitor(source.splitlines(), filepath)
        visitor.visit(tree)
        return visitor.findings

    def scan_directory(
        self, dirpath: str, recursive: bool = True, exclude_tests: bool = False
    ) -> List[Finding]:
        """
        Scan all .py files in a directory for JWT misuse patterns.

        Skips hidden directories and common non-source directories. When
        ``recursive`` is False only the top-level directory is scanned. When
        ``exclude_tests`` is True, files that look like test or fixture code
        (test_*.py, *_test.py, conftest.py, or anything under a tests/ tree)
        are skipped — useful for production-deployment scans.
        """
        findings: List[Finding] = []
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_DIRS and not d.startswith('.')
                and not (exclude_tests and d.lower() in _TEST_DIR_NAMES)
            ]
            if not recursive:
                dirs.clear()
            for filename in files:
                if not filename.endswith('.py'):
                    continue
                filepath = os.path.join(root, filename)
                if exclude_tests and _is_test_path(filepath):
                    continue
                findings.extend(self.scan_file(filepath))
        return findings
