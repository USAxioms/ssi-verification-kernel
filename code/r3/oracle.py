"""Third, independent implementation of WAD-18 add/sub/mul/div (pure Python integers).
Used by the R3 evidence pass to recompute every WAD/WADX line of the C table from its operands."""
SCALE = 10**18
WAD_MAX = 2**127 - 1
WAD_MIN = -WAD_MAX

def _finish(n, d):
    q, r = abs(n) // abs(d), abs(n) % abs(d)
    if q > WAD_MAX: return ("ERR", "OVERFLOW")
    if r: return ("ERR", "NON_EXACT")
    return ("OK", str(-q if (n < 0) != (d < 0) else q))

def compute(op, a, b):
    if op in ("add", "sub"):
        r = a + b if op == "add" else a - b
        return ("OK", str(r)) if WAD_MIN <= r <= WAD_MAX else ("ERR", "OVERFLOW")
    if op == "mul": return _finish(a * b, SCALE)
    if b == 0: return ("ERR", "DIV_ZERO")
    return _finish(a * SCALE, b)

def check_line(line):
    """Return None if the line agrees with the oracle, else a description. Lines that are not WAD/WADX return None."""
    f = line.split(" ")
    if f[0] not in ("WAD", "WADX"): return None
    op, a, b, status, val = f[1], int(f[2]), int(f[3]), f[4], f[5]
    want = compute(op, a, b)
    return None if (status, val) == want else f"{line}  oracle={want}"
