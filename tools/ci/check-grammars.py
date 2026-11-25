# SPDX-FileCopyrightText: 2026 Nicole Roy
# SPDX-License-Identifier: MPL-2.0

"""Checks every grammar in grammars/ (ADR 0013, rule 6).

Every *.abnf file must parse as RFC 5234 ABNF. Where a *.vectors file sits
beside it, each vector must agree with the grammar: "ok" lines match the
rule named by the file's "# rule:" directive (within its "# max-length:",
if it has one), and "err" lines don't.

Vectors are written one per line: "ok" or "err", a tab, then the text with
C-style escapes: \\t, \\\\, \\" and \\xHH. A tag may name its own rule,
as in "ok@header". Usage: check-grammars.py [dir]
"""

import pathlib
import re
import sys

from abnf import Rule
from abnf.parser import ParseError


def decode(text: str) -> bytes:
    out, b, i = bytearray(), text.encode("utf-8"), 0
    while i < len(b):
        if b[i] != 0x5C:
            out.append(b[i])
            i += 1
            continue
        nxt = b[i + 1 : i + 2]
        if nxt == b"t":
            out.append(9)
            i += 2
        elif nxt == b"\\":
            out.append(0x5C)
            i += 2
        elif nxt == b'"':
            out.append(0x22)
            i += 2
        elif nxt == b"x":
            out.append(int(b[i + 2 : i + 4], 16))
            i += 4
        else:
            raise ValueError(f"bad escape in {text!r}")
    return bytes(out)


def check(abnf: pathlib.Path) -> int:
    class Grammar(Rule):
        pass

    try:
        Grammar.load_grammar(abnf.read_text(encoding="ascii"))
    except Exception as e:  # noqa: BLE001 - any failure is a bad grammar
        print(f"FAIL {abnf}: doesn't parse as ABNF: {e}")
        return 1
    vectors = abnf.with_suffix(".vectors")
    if not vectors.exists():
        print(f"ok   {abnf}: parses (no vectors)")
        return 0
    text = vectors.read_text(encoding="utf-8")
    rule_name = re.search(r"^# rule: (\S+)$", text, re.M)
    max_len = re.search(r"^# max-length: (\d+)$", text, re.M)
    if not rule_name:
        print(f"FAIL {vectors}: no '# rule:' directive")
        return 1
    default_rule = rule_name.group(1)
    limit = int(max_len.group(1)) if max_len else None
    good = bad = 0
    for n, raw in enumerate(text.split("\n"), 1):
        if not raw or raw.startswith("#"):
            continue
        tag, _, body = raw.partition("\t")
        tag, _, which = tag.partition("@")
        rule = Grammar(which or default_rule)
        if tag not in ("ok", "err"):
            print(f"FAIL {vectors}:{n}: expected 'ok' or 'err'")
            bad += 1
            continue
        line = decode(body)
        try:
            rule.parse_all(line.decode("latin-1"))
            matches = True
        except ParseError:
            matches = False
        accepted = matches and (limit is None or len(line) <= limit)
        if accepted != (tag == "ok"):
            print(f"FAIL {vectors}:{n}: {tag}, but the grammar {'accepts' if accepted else 'rejects'} it")
            bad += 1
        else:
            good += 1
    print(f"{'ok  ' if not bad else 'FAIL'} {abnf}: {good} vectors agree, {bad} disagree")
    return 1 if bad else 0


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "grammars")
    # Names with a space are iCloud's conflict copies, such as "initfs 2.abnf".
    grammars = sorted(g for g in root.glob("*.abnf") if " " not in g.name)
    if not grammars:
        print(f"no grammars in {root}")
        return 1
    return 1 if sum(check(g) for g in grammars) else 0


if __name__ == "__main__":
    sys.exit(main())
