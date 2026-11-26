# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

"""Checks every grammar in grammars/ (ADR 0013, rule 6; ADR 0062, rule 8).

Every *.abnf file must parse as RFC 5234 ABNF, updated by RFC 7405. Where a
*.vectors file sits beside it, each vector must agree with the grammar:
"ok" lines match their rule (within the file's "# max-length:", if it has
one), and "err" lines don't. A line names its rule with "@", as in
"ok@header", or takes the file's "# rule:" directive.

This checker reads the context-free grammar only. It can't bind a length
to a repetition, so it checks no constraint: it reads "errc" (a vector that
matches the grammar but breaks a constraint) as "ok", and it validates the
"# caps:" and "# unwrapped:" directives without judging by them. crates/abnf,
the Rust checker, also enforces the constraints. The two are a differential
pair (docs/design/call-language.md, "Checkers").

A grammar's header may say "; uses: core, names": those grammars, from the
same directory, load first into the same rule class, transitively. No
grammar but core.abnf may define a core rule name, in any letter case, so
core.abnf must sit beside the grammars.

Vectors are written one per line: a tag, a tab, then the octets with
C-style escapes: \\t, \\\\, \\" and \\xHH. Usage: check-grammars.py [dir]
"""

import pathlib
import re
import sys
import warnings

from abnf import Rule
from abnf.parser import GrammarError, GrammarWarning, ParseError

# The shared spellings. crates/abnf reads the same forms the same way.
RULENAME = r"[A-Za-z][A-Za-z0-9-]*"
# A comment whose text starts with "uses:" is a uses line, and must be
# exactly this, at column 0, before the first rule.
USES_LIKE = re.compile(r";[ \t]*uses:")
USES = re.compile(r"; uses: ([a-z][a-z0-9-]*(?:, [a-z][a-z0-9-]*)*)")
# A "#" line naming a directive keyword is a directive, and must be exactly
# "# keyword: value"; any other "#" line is a comment.
DIRECTIVE_LIKE = re.compile(r"#[ \t]*(rule|max-length|caps|unwrapped)[ \t]*:")
DIRECTIVE = re.compile(r"# (rule|max-length|caps|unwrapped): (\S(?:.*\S)?)")
TAG = re.compile(rf"(ok|err|errc)(?:@({RULENAME}))?")
ESCAPE = re.compile(r"\\(t|\\|\"|x[0-9A-Fa-f]{2})")
# A rule definition: a rulename at column 0, then c-wsp (which may cross
# a line end that a space or tab follows), then "=" or "=/".
DEFINITION = re.compile(rf"^({RULENAME})(?:[ \t]|(?:;[^\n]*)?\n[ \t])*(=/|=)", re.M)
NUM_VAL = re.compile(
    r"%(?:([bB])([01]+(?:[.-][01]+)*)|([dD])([0-9]+(?:[.-][0-9]+)*)|([xX])([0-9A-Fa-f]+(?:[.-][0-9A-Fa-f]+)*))"
)
REPEAT = re.compile(r"(?<![A-Za-z0-9-])(?:([0-9]*)\*([0-9]*)|([0-9]+))")
U32_MAX = 2**32 - 1


class Fail(Exception):
    """A grammar or vector file that breaks a rule this checker enforces."""


def read_ascii(path: pathlib.Path) -> str:
    """The grammar's text, with CRLF read as LF. Any octet outside ASCII's
    printable range, tab and line feed, and a CR not before LF, fail."""
    raw = path.read_bytes()
    for i, b in enumerate(raw):
        if b == 0x0D:
            if raw[i + 1 : i + 2] != b"\n":
                raise Fail(f"{path}: a CR not followed by LF")
        elif not (0x20 <= b <= 0x7E or b in (0x09, 0x0A)):
            raise Fail(f"{path}: octet 0x{b:02x} isn't ASCII text")
    return raw.decode("ascii").replace("\r\n", "\n")


def code_and_comment(line: str) -> tuple[str, str]:
    """Splits a grammar line at its comment: the first ";" outside a
    char-val ("...") or a prose-val (<...>)."""
    i = 0
    while i < len(line):
        c = line[i]
        if c in "\"<":
            end = line.find('"' if c == '"' else ">", i + 1)
            if end < 0:
                return line, ""
            i = end + 1
        elif c == ";":
            return line[:i], line[i:]
        else:
            i += 1
    return line, ""


def uses_of(path: pathlib.Path, text: str) -> list[str]:
    """The names a grammar's "; uses:" header lines list."""
    names: list[str] = []
    header = True
    for n, line in enumerate(text.split("\n"), 1):
        if re.match(r"[A-Za-z]", line):
            header = False
        _, comment = code_and_comment(line)
        if not USES_LIKE.match(comment):
            continue
        m = USES.fullmatch(line)
        if not header or not m:
            raise Fail(f"{path}:{n}: a uses line is '; uses: ' and names, before the first rule")
        for name in m.group(1).split(", "):
            if name in names:
                raise Fail(f"{path}:{n}: uses {name} twice")
            names.append(name)
    return names


def load_order(path: pathlib.Path) -> list[pathlib.Path]:
    """The grammars that `path` uses, transitively, each before the grammars
    that use it, and each once. A cycle or a missing grammar fails."""
    order: list[pathlib.Path] = []
    done: set[str] = set()
    visiting: list[str] = []

    def visit(p: pathlib.Path) -> None:
        if p.stem in done:
            return
        if p.stem in visiting:
            raise Fail(f"{path}: uses cycle: {' -> '.join(visiting + [p.stem])}")
        if not p.exists():
            raise Fail(f"{path}: uses {p.stem}, but there is no {p}")
        visiting.append(p.stem)
        for name in uses_of(p, read_ascii(p)):
            visit(p.parent / f"{name}.abnf")
        visiting.pop()
        done.add(p.stem)
        order.append(p)

    visit(path)
    return order


def check_text(path: pathlib.Path, text: str, core_names: set[str]) -> None:
    """The checks abnf 2.9.1 doesn't make: rule definitions, reserved names,
    octet values (ADR 0062, rule 1) and repeat counts."""
    defined: set[str] = set()
    for m in DEFINITION.finditer(text):
        name, op = m.group(1), m.group(2)
        key = name.lower()
        n = text.count("\n", 0, m.start()) + 1
        if key in core_names and path.name != "core.abnf":
            raise Fail(f"{path}:{n}: defines core rule name {name} (ADR 0062, rule 3)")
        if op == "=" and key in defined:
            raise Fail(f"{path}:{n}: defines {name} twice")
        if op == "=/" and key not in defined:
            raise Fail(f"{path}:{n}: '=/' on {name}, which this file hasn't defined")
        defined.add(key)
    for n, line in enumerate(text.split("\n"), 1):
        code, _ = code_and_comment(line)
        code = re.sub(r'"[^"]*"|<[^>]*>', " ", code)
        for m in NUM_VAL.finditer(code):
            base = 2 if m.group(1) else 10 if m.group(3) else 16
            digits = m.group(2) or m.group(4) or m.group(6)
            values = [int(v, base) for v in re.split(r"[.-]", digits)]
            if max(values) > 255:
                raise Fail(f"{path}:{n}: {m.group(0)}: a terminal value is one octet (ADR 0062, rule 1)")
            if "-" in digits and values[0] > values[1]:
                raise Fail(f"{path}:{n}: {m.group(0)}: an empty range")
        code = NUM_VAL.sub(" ", code)
        for m in REPEAT.finditer(code):
            lo, hi = (m.group(1), m.group(2)) if m.group(3) is None else (m.group(3), m.group(3))
            lo_v = int(lo) if lo else 0
            hi_v = int(hi) if hi else None
            if lo_v > U32_MAX or (hi_v is not None and (hi_v > U32_MAX or lo_v > hi_v)):
                raise Fail(f"{path}:{n}: repeat {m.group(0)} is out of range")


def decode(text: str) -> bytes:
    """A vector's body: \\t, \\\\, \\" and \\xHH escapes, every other octet
    standing for itself. Any other backslash sequence fails."""
    out, i = bytearray(), 0
    while i < len(text):
        if text[i] != "\\":
            out += text[i].encode("utf-8")
            i += 1
            continue
        m = ESCAPE.match(text, i)
        if not m:
            raise ValueError(f"bad escape at {text[i : i + 4]!r}")
        e = m.group(1)
        out.append(int(e[1:], 16) if e[0] == "x" else {"t": 9, "\\": 0x5C, '"': 0x22}[e])
        i = m.end()
    return bytes(out)


def check(abnf: pathlib.Path, core_names: set[str]) -> int:
    class Grammar(Rule):
        pass

    try:
        files = load_order(abnf)
        for f in files:
            check_text(f, read_ascii(f), core_names)
        # A redefinition is an error, not a warning.
        with warnings.catch_warnings():
            warnings.simplefilter("error", GrammarWarning)
            for f in files:
                Grammar.load_grammar(read_ascii(f))
    except Fail as e:
        print(f"FAIL {e}")
        return 1
    except Exception as e:  # noqa: BLE001 - any failure is a bad grammar
        print(f"FAIL {abnf}: doesn't parse as ABNF: {e}")
        return 1
    vectors = abnf.with_suffix(".vectors")
    if not vectors.exists():
        print(f"ok   {abnf}: parses (no vectors)")
        return 0
    raw = vectors.read_bytes()
    if b"\r" in raw:
        print(f"FAIL {vectors}: holds a CR; write it as \\x0d")
        return 1
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        print(f"FAIL {vectors}: isn't UTF-8: {e}")
        return 1
    lines = text.split("\n")

    # Directives: "# rule:" and "# max-length:" hold for the whole file, and
    # each appears at most once. "# caps:" and "# unwrapped:" are positional.
    default_rule, limit, seen = None, None, set()
    for n, line in enumerate(lines, 1):
        if not DIRECTIVE_LIKE.match(line):
            continue
        m = DIRECTIVE.fullmatch(line)
        key, value = (m.group(1), m.group(2)) if m else (None, None)
        ok = m is not None and (
            (key == "rule" and re.fullmatch(RULENAME, value))
            or (key == "max-length" and re.fullmatch(r"[0-9]+", value) and int(value) < 2**64)
            or (key == "caps" and re.fullmatch(r"[0-3]", value))
            or (key == "unwrapped" and re.fullmatch(r"[0-9A-Fa-f]", value))
        )
        if not ok:
            print(f"FAIL {vectors}:{n}: a malformed directive")
            return 1
        if key in ("rule", "max-length"):
            if key in seen:
                print(f"FAIL {vectors}:{n}: a second '# {key}:'")
                return 1
            seen.add(key)
            if key == "rule":
                default_rule = value
            else:
                limit = int(value)

    good = bad = errc = 0
    caps = unwrapped = 0
    for n, line in enumerate(lines, 1):
        if not line:
            continue
        if line.startswith("#"):
            m = DIRECTIVE_LIKE.match(line) and DIRECTIVE.fullmatch(line)
            if m and m.group(1) == "caps":
                caps, unwrapped = int(m.group(2)), 0
            elif m and m.group(1) == "unwrapped":
                unwrapped = int(m.group(2), 16)
                if unwrapped >> caps:
                    print(f"FAIL {vectors}:{n}: unwrapped bits beyond the capability count {caps}")
                    bad += 1
            continue
        head, tab, body = line.partition("\t")
        tag = TAG.fullmatch(head)
        if not tab or not tag:
            print(f"FAIL {vectors}:{n}: expected 'ok', 'err' or 'errc', an optional '@rule', and a tab")
            bad += 1
            continue
        which = tag.group(2) or default_rule
        if which is None:
            print(f"FAIL {vectors}:{n}: no '@rule' and no '# rule:' directive")
            bad += 1
            continue
        try:
            octets = decode(body)
            try:
                Grammar(which).parse_all(octets.decode("latin-1"))
                matches = True
            except ParseError:
                matches = False
        except (ValueError, GrammarError) as e:
            print(f"FAIL {vectors}:{n}: {e}")
            bad += 1
            continue
        accepted = matches and (limit is None or len(octets) <= limit)
        if tag.group(1) == "errc":
            errc += 1
        if accepted != (tag.group(1) != "err"):
            print(f"FAIL {vectors}:{n}: {tag.group(1)}, but the grammar {'accepts' if accepted else 'rejects'} it")
            bad += 1
        else:
            good += 1
    note = f" ({errc} errc, read as ok)" if errc else ""
    print(f"{'ok  ' if not bad else 'FAIL'} {abnf}: {good} vectors agree{note}, {bad} disagree")
    return 1 if bad else 0


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "grammars")
    # Names with a space are iCloud's conflict copies, such as "initfs 2.abnf".
    grammars = sorted(g for g in root.glob("*.abnf") if " " not in g.name)
    if not grammars:
        print(f"no grammars in {root}")
        return 1
    core = root / "core.abnf"
    if not core.exists():
        print(f"FAIL {core}: missing; it holds the reserved rule names (ADR 0062, rule 3)")
        return 1
    try:
        core_names = {m.group(1).lower() for m in DEFINITION.finditer(read_ascii(core))}
    except Fail as e:
        print(f"FAIL {e}")
        return 1
    return 1 if sum(check(g, core_names) for g in grammars) else 0


if __name__ == "__main__":
    sys.exit(main())
