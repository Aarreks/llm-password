"""Generate stage0_bad_substrings.csv for the Stage 0 Aho-Corasick matcher.

This resource is meant to catch compact sequence-like substrings that zxcvbn can
overcredit when they are embedded inside a longer string. Matches are not hard
rejects by themselves; they add cheap span explanations to the Stage 0 interval DP.
"""
from __future__ import annotations

import csv, json
from pathlib import Path

HEADER = ["substring", "family", "log10_span_cost", "action", "note", "params"]


def add(rows, seen, substring, family, cost, note, **params):
    s = str(substring).lower()
    if len(s) < 4 or s in seen:
        return
    seen.add(s)
    rows.append({
        "substring": s,
        "family": family,
        "log10_span_cost": cost,
        "action": "score_only",
        "note": note,
        "params": json.dumps(params, separators=(",", ":")),
    })


def generate_rows():
    rows, seen = [], set()
    letters = "abcdefghijklmnopqrstuvwxyz"
    fixed_chars = ["-", ".", "_", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]

    # Alphabet progressions with a repeated fixed prefix, e.g. 1a1b1c1d.
    for fixed in fixed_chars:
        for length in range(6, 16):
            for start in range(0, 26 - length + 1):
                seq = ''.join(fixed + ch for ch in letters[start:start+length])
                add(rows, seen, seq, "alphabet_fixed_prefix", 3.0,
                    "Alphabet progression with the same prefix before each letter, e.g. 1a1b1c1d.",
                    fixed=fixed, start_letter=letters[start], length=length)

    # No-separator decimal counts, e.g. 1011121314 or 100101102103.
    for start in range(0, 250):
        for length in range(5, 13):
            nums = list(range(start, start+length))
            seq = ''.join(map(str, nums))
            cost = 3.0 if length >= 6 else 3.5
            add(rows, seen, seq, "decimal_count_no_separator", cost,
                "Consecutive decimal count concatenated without separators, e.g. 101112131415.",
                start=start, step=1, length=length)

    # Arithmetic progressions with no separators, including odd/even-ish tails.
    for start in range(0, 200):
        for step in range(2, 11):
            for length in range(5, 11):
                nums = [start + step*k for k in range(length)]
                seq = ''.join(map(str, nums))
                add(rows, seen, seq, "arithmetic_progression_no_separator", 3.8,
                    "Arithmetic progression concatenated without separators, e.g. 111315171921.",
                    start=start, step=step, length=length)

    # Binary count concatenations.
    for start in range(0, 64):
        for length in range(6, 16):
            seq = ''.join(bin(x)[2:] for x in range(start, start+length))
            add(rows, seen, seq, "binary_count_concat", 3.5,
                "Consecutive binary numbers concatenated without separators.",
                start=start, length=length)

    # A tiny set of explicit compact sequences and code-ish fragments.
    specials = [
        ("1234567890", "classic_digit_sequence", 1.5),
        ("9876543210", "classic_digit_sequence", 1.5),
        ("qwertyuiop", "keyboard_walk", 2.0),
        ("asdfghjkl", "keyboard_walk", 2.0),
        ("for(inti=0;i<n;i++)", "code_fragment_normalized", 4.0),
    ]
    for s, fam, cost in specials:
        add(rows, seen, s, fam, cost, "Small explicit list of very common compact patterns.")

    rows.sort(key=lambda r: (r["family"], r["substring"]))
    return rows


def main(out_path="data/stage0_bad_substrings.csv"):
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = generate_rows()
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADER)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
