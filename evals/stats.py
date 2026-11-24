"""Statistics of the November pre-registration (tmp/rag1/PREREG.md section 3 to 5), stdlib only.

Paired tables are (a, b, c, d) = (both held, only X held, only Y held, neither held); differences are X - Y.
"""
import math

Z = 1.959963984540054


def wilson(k, n, z=Z):
    if n == 0:
        return 0.0, 1.0
    p, z2 = k / n, z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return centre - half, centre + half


def mcnemar_exact(b, c):
    """Two-sided exact McNemar p: 2 x P(Binomial(b + c, 1/2) <= min(b, c)), capped at 1."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def holm(ps):
    """Holm step-down adjusted p-values, in the order given."""
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    out, running = [0.0] * len(ps), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(ps) - rank) * ps[i]))
        out[i] = running
    return out


def newcombe(p1, l1, u1, p2, l2, u2, phi):
    """Newcombe (1998) method 10: interval for p1 - p2 from two Wilson intervals and the correlation phi (0 for independent samples)."""
    lo = (p1 - p2) - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2 - 2 * phi * (p1 - l1) * (u2 - p2))
    hi = (p1 - p2) + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2 - 2 * phi * (u1 - p1) * (p2 - l2))
    return lo, hi


def paired_interval(a, b, c, d):
    """Newcombe 95% interval (diff, lo, hi) of (share held by X) - (share held by Y), with his correction of phi:
    the numerator ad - bc is cut by n/2 above n/2, zeroed from 0 to n/2, kept below 0."""
    n = a + b + c + d
    p1, p2 = (a + b) / n, (a + c) / n
    den = math.sqrt((a + b) * (c + d) * (a + c) * (b + d))
    cross = a * d - b * c
    cross = cross - n / 2 if cross > n / 2 else 0.0 if cross >= 0 else cross
    phi = cross / den if den else 0.0
    return p1 - p2, *newcombe(p1, *wilson(a + b, n), p2, *wilson(a + c, n), phi)
