"""PURE WAD¹⁸ source scan: strip comments and string/char literals, then forbid
floating-point types, math.h, Math.*, and decimal or exponent numeric literals in code."""
import re, sys, glob

def strip(src):
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2); i = n if j < 0 else j + 2
        elif src[i] in "\"'`":
            q = src[i]; i += 1
            while i < n and src[i] != q:
                i += 2 if src[i] == "\\" else 1
            i += 1; out.append(" ")
        else:
            out.append(src[i]); i += 1
    return "".join(out)

RULES = [
    (r"\b(float|double)\b", "floating-point type"),
    (r"#\s*include\s*<math\.h>", "math.h"),
    (r"\bMath\.", "JavaScript Math"),
    (r"(?<![\w.])\d+\.\d*(?:[eE][-+]?\d+)?[fFlL]?(?![\w])|(?<![\w.])\d+[eE][-+]?\d+(?![\w])", "decimal or exponent literal"),
]
files = sorted(glob.glob("src/*.c") + glob.glob("include/*.h") + glob.glob("tests/*.c") + glob.glob("ts/*.ts"))
bad = 0
for f in files:
    code = strip(open(f, encoding="utf-8").read())
    for ln, line in enumerate(code.split("\n"), 1):
        for pat, what in RULES:
            if re.search(pat, line):
                print(f"    {f}:{ln}: {what}: {line.strip()}"); bad += 1
print(f"    scanned {len(files)} files: {bad} violation(s)")
sys.exit(1 if bad else 0)
