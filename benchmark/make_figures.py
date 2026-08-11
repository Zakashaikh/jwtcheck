"""
make_figures.py — turn captured evaluation output into dissertation figures.

Produces, for each evaluation suite, both candidate formats so the author can
choose one and delete the other:

    benchmark/figures/<n>_<slug>.html   terminal-styled page, screenshot to PNG
    benchmark/figures/<n>_<slug>.tex    \\begin{figure} + lstlisting fragment

The text in both comes from the real captured runs in benchmark/figures/*.txt.
Long captures are excerpted, and every excerpt is labelled as one in the caption
so no figure implies it shows a complete run.

Usage:
    python benchmark/make_figures.py
"""

import html
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(HERE, "figures")

# (slug, title, source capture, caption, excerpt spec)
#   excerpt spec: None = whole file, or (head_lines, tail_lines)
FIGURES = [
    ("rule_corpus", "All fifteen rules on the demonstration corpus",
     "00_corpus_full.txt",
     "JWTCheck run over the 30-repository demonstration corpus. Excerpt: the "
     "first findings and the closing summary. All fifteen rules fire across the "
     "corpus; 232 findings in total.",
     (26, 2)),
    ("realworld", "Real-world study --- 96 repositories",
     "01_realworld_run.txt",
     "JWTCheck scanning the 96-repository quasi-random sample. Excerpt: the "
     "closing progress lines and the run summary. 332 findings, of which 321 "
     "were confirmed true positives (96.7\\% precision).",
     (0, 14)),
    ("portswigger", "PortSwigger JWT laboratory classes",
     "02_portswigger.txt",
     "Token-analyser evaluation against the eight PortSwigger JWT laboratory "
     "attack classes. Six of eight classes are surfaced; the two marked "
     "\\texttt{n/a} are server-side behaviours not decidable from a token alone.",
     None),
    ("tool_comparison", "Comparison against Bandit and Semgrep",
     "03_tool_comparison.txt",
     "JWTCheck compared with Bandit and Semgrep on the vulnerable-fixture set. "
     "Neither general-purpose tool detects any JWT misuse pattern; no tool "
     "produces false positives on the safe set.",
     None),
]

CSS = """
:root { color-scheme: dark; }
body { margin:0; background:#12141a; display:inline-block;
       font-family:'Cascadia Mono','Consolas',monospace; }
.term { display:inline-block; min-width:1100px; margin:0; background:#1b1e27; border-radius:10px;
        box-shadow:0 10px 40px rgba(0,0,0,.6); overflow:hidden; }
.bar  { background:#2a2e3a; padding:9px 14px; display:flex; align-items:center; gap:8px; }
.dot  { width:12px; height:12px; border-radius:50%; }
.t    { color:#9aa4bf; font-size:12.5px; margin-left:10px; letter-spacing:.02em; }
pre   { margin:0; padding:18px 20px; color:#d6dbe8; font-size:13.5px; line-height:1.5;
        white-space:pre; }
.cmd  { color:#6ee7a8; }
.crit { color:#ff6b6b; font-weight:700; }
.high { color:#ff9f5a; font-weight:700; }
.med  { color:#ffd166; font-weight:700; }
.pass { color:#6ee7a8; font-weight:700; }
.na   { color:#7c869e; }
.rule { color:#8ab4ff; font-weight:700; }
.dim  { color:#7c869e; }
.sum  { color:#ffffff; font-weight:700; }
"""


def colourise(text):
    t = html.escape(text)
    t = re.sub(r"^(CRITICAL)", r'<span class="crit">\1</span>', t, flags=re.M)
    t = re.sub(r"^(HIGH)", r'<span class="high">\1</span>', t, flags=re.M)
    t = re.sub(r"^(MEDIUM)", r'<span class="med">\1</span>', t, flags=re.M)
    t = re.sub(r"\[(PASS)\]", r'[<span class="pass">\1</span>]', t)
    t = re.sub(r"\[(n/a\s*)\]", r'[<span class="na">\1</span>]', t)
    t = re.sub(r"\b(R\d{2})\b", r'<span class="rule">\1</span>', t)
    t = re.sub(r"^(\s+Weakness:.*|\s+.*?:\d+:\d+)$", r'<span class="dim">\1</span>',
               t, flags=re.M)
    t = re.sub(r"^(Summary.*|Overall.*|Scanned.*|\s+JWTCheck\s+:.*|\s+Bandit\s+:.*|"
               r"\s+Semgrep\s+:.*|Token-detectable.*)$",
               r'<span class="sum">\1</span>', t, flags=re.M)
    return t


def excerpt(lines, spec):
    if spec is None:
        return lines
    head, tail = spec
    if len(lines) <= head + tail:
        return lines
    out = lines[:head] if head else []
    if head:
        out = out + ["", f"    ... {len(lines) - head - tail} lines omitted ...", ""]
    return out + (lines[-tail:] if tail else [])


def main():
    made = []
    for i, (slug, title, src, caption, spec) in enumerate(FIGURES, 1):
        path = os.path.join(FIG, src)
        if not os.path.isfile(path):
            print(f"  [skip] missing capture: {src}")
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            # The console encodes em dashes as cp1252, which surfaces either as
            # U+FFFD or as the classic "\u00e2\u20ac\u201d" mojibake once re-read as UTF-8.
            raw = (fh.read()
                   .replace("\u00e2\u0080\u0094", "\u2014")
                   .replace("\u00e2\u0080\u009d", "\u2014")
                   .replace("\ufffd", "\u2014"))
        lines = [l.rstrip() for l in raw.splitlines()]
        body = "\n".join(excerpt(lines, spec))

        cmd = {"rule_corpus": "jwtcheck scan rule_demo_corpus",
               "realworld": "python benchmark/run_real_world.py --no-clone",
               "portswigger": "python benchmark/portswigger_eval.py",
               "tool_comparison": "python benchmark/compare_tools.py"}[slug]

        # ---- HTML (screenshot to PNG) ----
        page = (
            # Served by a plain static server with no charset header, so the
            # declaration has to live in the document or em dashes render as
            # cp1252 mojibake.
            f"<meta charset='utf-8'>\n<style>{CSS}</style>\n<div class='term'>\n"
            f"  <div class='bar'><span class='dot' style='background:#ff5f57'></span>"
            f"<span class='dot' style='background:#febc2e'></span>"
            f"<span class='dot' style='background:#28c840'></span>"
            f"<span class='t'>{html.escape(title)}</span></div>\n"
            f"<pre><span class='cmd'>$ {html.escape(cmd)}</span>\n\n{colourise(body)}</pre>\n"
            f"</div>\n"
        )
        hp = os.path.join(FIG, f"{i:02d}_{slug}.html")
        with open(hp, "w", encoding="utf-8") as fh:
            fh.write(page)

        # ---- LaTeX listing ----
        tex = (
            "% Generated by benchmark/make_figures.py -- do not edit by hand.\n"
            "\\begin{figure}[htbp]\n\\centering\n"
            "\\begin{lstlisting}[basicstyle=\\ttfamily\\scriptsize,frame=single,"
            "breaklines=true,columns=fullflexible]\n"
            f"$ {cmd}\n\n{body}\n"
            "\\end{lstlisting}\n"
            f"\\caption{{{caption}}}\n"
            f"\\label{{fig:{slug.replace('_', '-')}}}\n"
            "\\end{figure}\n"
        )
        tp = os.path.join(FIG, f"{i:02d}_{slug}.tex")
        with open(tp, "w", encoding="utf-8") as fh:
            fh.write(tex)

        made.append((slug, len(body.splitlines()), hp, tp))

    print(f"{len(made)} figure pair(s):")
    for slug, n, hp, tp in made:
        print(f"  {slug:<18} {n:>4} lines   {os.path.basename(hp)} + {os.path.basename(tp)}")


if __name__ == "__main__":
    main()
