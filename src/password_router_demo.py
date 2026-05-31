"""Extracted code from notebooks/final_password_router_demo.ipynb.
Prefer the notebook for interactive Colab use.
"""

# %%
import os, re, gc, csv, json, math, time, hashlib, datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

import requests
import pandas as pd
from tqdm.auto import tqdm

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

import zxcvbn as zxcvbn_pkg
import ahocorasick

QWEN_15B_MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct"
SEVEN_B_MODEL_ID = "mistralai/Mistral-7B-Instruct-v0.3"
BAD_SUBSTRING_CSV = "data/stage0_bad_substrings.csv"

MAX_PASSWORDS = 1000

STAGE0_REJECT_ZXCVBN_LOG10 = 10.0
STAGE0_REJECT_PATCHED_LOG10 = 10.0
VARIANT_PWN_CHANGED_LEN_REJECT_CUTOFF = 4

# Stable patched Stage 0 candidate generation.
# This fixes the zxcvbn-match-list instability where a substring such as
# "wolf" or "go" may appear only after an unrelated suffix is appended.
STABLE_ZXCVBN_SUBSTRING_MIN_LEN = 2
STABLE_ZXCVBN_SUBSTRING_MAX_LEN = 32
STABLE_ZXCVBN_MAX_PASSWORD_LEN = 96
STABLE_ZXCVBN_MAX_SUBSTRING_CALLS = 2500
STABLE_ZXCVBN_KEEP_MARGIN_LOG10 = 0.05

DP_REJECT_LOG10 = 20.0
DP_ACCEPT_LOG10 = 32.0

BEAM_PER_INDEX = 32
MAX_VALID_TOKENS_PER_STATE = 32
BATCH_STATES = 32

# Experiment-1-style raw token DP: one exact continuation DP per password per stage.
# No user-provided separators. No loop over all split positions.
# The default scores the whole raw password as the exact generated target.
AUTO_PREFIX_CHARS = 0

def template_A0(prefix: str) -> str:
    return f"Very long but vulnerable password: {prefix}"

def template_C3(prefix: str) -> str:
    return f"Task: continue the password prefix.\nPrefix: {prefix}\nContinuation:"

TEMPLATES = {
    "A0_current_vulnerable": template_A0,
    "C3_task_continue_field": template_C3,
}

print("Config ready.")
print("1.5B model:", QWEN_15B_MODEL_ID)
print("7B model:", SEVEN_B_MODEL_ID)

# %%
# If the Aho CSV is not present, upload it now.
# It should be the stage0_bad_substrings.csv file from the GitHub repo.

if not Path(BAD_SUBSTRING_CSV).exists():
    print(f"{BAD_SUBSTRING_CSV!r} not found in the current directory.")
    print("Upload stage0_bad_substrings.csv now, or clone the repo and run from its root directory.")
    try:
        from google.colab import files
        uploaded = files.upload()
        if BAD_SUBSTRING_CSV not in uploaded:
            csvs = [name for name in uploaded if name.endswith(".csv")]
            if csvs:
                Path(csvs[0]).rename(BAD_SUBSTRING_CSV)
                print(f"Renamed {csvs[0]!r} to {BAD_SUBSTRING_CSV!r}")
    except Exception as e:
        print("Upload helper not available:", e)

if not Path(BAD_SUBSTRING_CSV).exists():
    raise FileNotFoundError(f"Need {BAD_SUBSTRING_CSV}. Upload it or place it beside the notebook.")

print("Aho CSV found:", BAD_SUBSTRING_CSV)

# %%
@dataclass
class AhoMatch:
    substring: str
    family: str
    log10_span_cost: float
    action: str
    note: str
    start: int
    end: int
    matched_text: str
    params: str = ""

class BadSubstringMatcher:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.automaton = ahocorasick.Automaton()
        self.num_patterns = 0

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pat = row["substring"].strip().lower()
                if not pat:
                    continue
                meta = {
                    "substring": pat,
                    "family": row.get("family", ""),
                    "log10_span_cost": float(row.get("log10_span_cost", "3.0")),
                    "action": row.get("action", "score_only"),
                    "note": row.get("note", ""),
                    "params": row.get("params", ""),
                }
                self.automaton.add_word(pat, meta)
                self.num_patterns += 1

        self.automaton.make_automaton()

    def find(self, password: str) -> List[AhoMatch]:
        s = password.lower()
        matches = []
        for end_idx, meta in self.automaton.iter(s):
            start_idx = end_idx - len(meta["substring"]) + 1
            matches.append(AhoMatch(
                substring=meta["substring"],
                family=meta["family"],
                log10_span_cost=meta["log10_span_cost"],
                action=meta["action"],
                note=meta["note"],
                start=start_idx,
                end=end_idx + 1,
                matched_text=password[start_idx:end_idx + 1],
                params=meta.get("params", ""),
            ))

        matches.sort(key=lambda m: (m.start, -(m.end - m.start), m.log10_span_cost))
        filtered = []
        for m in matches:
            dominated = False
            for k in filtered:
                if k.start <= m.start and m.end <= k.end and k.log10_span_cost <= m.log10_span_cost:
                    dominated = True
                    break
            if not dominated:
                filtered.append(m)
        return filtered

BAD_MATCHER = BadSubstringMatcher(BAD_SUBSTRING_CSV)
print("Loaded Aho patterns:", BAD_MATCHER.num_patterns)

# %%
def safe_log10(x: float) -> float:
    if x <= 0:
        return float("-inf")
    return math.log10(x)

def zxcvbn_score(password: str) -> Dict[str, Any]:
    r = zxcvbn_pkg.zxcvbn(password)
    r["guesses_log10_float"] = safe_log10(float(r.get("guesses", 0)))
    return r

def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest().upper()

_hibp_cache: Dict[str, Dict[str, int]] = {}

def hibp_range_lookup_sha1(sha1: str) -> Tuple[bool, int, str]:
    prefix, suffix = sha1[:5], sha1[5:]
    if prefix not in _hibp_cache:
        try:
            resp = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=8,
                headers={"Add-Padding": "true"},
            )
            resp.raise_for_status()
            d = {}
            for line in resp.text.splitlines():
                if ":" in line:
                    suf, cnt = line.split(":", 1)
                    try:
                        d[suf.strip().upper()] = int(cnt.strip())
                    except Exception:
                        pass
            _hibp_cache[prefix] = d
        except Exception as e:
            return False, 0, f"lookup_failed:{type(e).__name__}"
    cnt = _hibp_cache[prefix].get(suffix, 0)
    return cnt > 0, cnt, "ok"

def pwned_count(password: str) -> Tuple[bool, int, str]:
    return hibp_range_lookup_sha1(sha1_hex(password))

LEET_TABLE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"
})

def generate_pwn_variants(password: str) -> List[Tuple[str, str, int]]:
    variants = []
    def add(name, s):
        if s and s != password and len(s) >= 4:
            changed = abs(len(password) - len(s))
            variants.append((name, s, changed))

    add("lowercase", password.lower())
    add("strip_trailing_punct", re.sub(r"[^\w]+$", "", password))
    add("strip_trailing_digits", re.sub(r"\d+$", "", password))
    add("strip_year_suffix", re.sub(r"(19|20)\d\d$", "", password))
    add("remove_separators", re.sub(r"[-_\s.]+", "", password))
    add("leet_normalized", password.translate(LEET_TABLE))
    add("lowercase_strip_trailing_digits", re.sub(r"\d+$", "", password.lower()))
    add("lowercase_remove_separators", re.sub(r"[-_\s.]+", "", password.lower()))
    add("leet_lowercase", password.translate(LEET_TABLE).lower())

    out, seen = [], set()
    for name, s, changed in variants:
        if s not in seen:
            out.append((name, s, changed))
            seen.add(s)
    return out[:12]

COMMON_BIGRAMS = {
    "th","he","in","er","an","re","on","at","en","nd","ti","es","or","te","of","ed","is",
    "it","al","ar","st","to","nt","ng","se","ha","as","ou","io","le","ve","co","me","de"
}

def brute_char_cost(ch: str) -> float:
    if ch.islower() or ch.isupper():
        return math.log10(26)
    if ch.isdigit():
        return math.log10(10)
    return math.log10(33)

def brute_span_cost(span: str) -> float:
    return sum(brute_char_cost(ch) for ch in span)

def markovish_alpha_cost(span: str) -> float:
    if not re.fullmatch(r"[A-Za-z]{4,}", span or ""):
        return float("inf")
    s = span.lower()
    n = len(s)
    uniform = n * math.log10(26)

    vowels = sum(ch in "aeiou" for ch in s)
    vowel_ratio = vowels / max(1, n)
    bigrams = [s[i:i+2] for i in range(n - 1)]
    common_frac = sum(bg in COMMON_BIGRAMS for bg in bigrams) / max(1, len(bigrams))

    penalty = 0.0
    if 0.20 <= vowel_ratio <= 0.55:
        penalty += 0.18 * n
    if common_frac >= 0.20:
        penalty += 0.15 * n
    if common_frac >= 0.35:
        penalty += 0.10 * n

    return max(0.0, uniform - penalty)

def zxcvbn_match_cost(match: Dict[str, Any]) -> float:
    guesses = match.get("guesses", None)
    if guesses is None:
        if match.get("guesses_log10", None) is not None:
            return float(match["guesses_log10"])
        return brute_span_cost(match.get("token", ""))
    try:
        return safe_log10(float(guesses))
    except Exception:
        return brute_span_cost(match.get("token", ""))


_zxcvbn_span_cache: Dict[str, List[Tuple[int, float, str, str]]] = {}

def _match_span_indices(m: Dict[str, Any], n: int) -> Optional[Tuple[int, int]]:
    """Return 0-based [i,j) indices for one zxcvbn match object when available."""
    if "i" in m and "j" in m:
        i, j = int(m["i"]), int(m["j"]) + 1
        if 0 <= i < j <= n:
            return i, j
    return None

def stable_zxcvbn_substring_candidates(password: str) -> List[Tuple[int, int, float, str, str]]:
    """Enumerate zxcvbn-like substring candidates consistently.

    zxcvbn's match list for the full password is not stable under suffix changes.
    Example: appending one more repeated digit may make zxcvbn expose `wolf` and `go`
    as dictionary matches even though those substrings were already present.

    This function checks substrings directly and adds full-span zxcvbn matches whose
    estimated cost is lower than brute force. That makes dictionary chunks such as
    `wolf` and `go` available for every password containing them, not only when
    zxcvbn happens to return them in the whole-string sequence.
    """
    n = len(password)
    out: List[Tuple[int, int, float, str, str]] = []
    if n == 0 or n > STABLE_ZXCVBN_MAX_PASSWORD_LEN:
        return out

    calls = 0
    max_len = min(STABLE_ZXCVBN_SUBSTRING_MAX_LEN, n)
    for i in range(n):
        upper = min(n, i + max_len)
        for j in range(i + STABLE_ZXCVBN_SUBSTRING_MIN_LEN, upper + 1):
            if calls >= STABLE_ZXCVBN_MAX_SUBSTRING_CALLS:
                return out
            span = password[i:j]
            # Single characters are handled by brute_char. Whitespace-only spans are not useful here.
            if not span.strip():
                continue
            calls += 1
            if span not in _zxcvbn_span_cache:
                try:
                    rz = zxcvbn_pkg.zxcvbn(span)
                    candidates: List[Tuple[int, float, str, str]] = []
                    brute = brute_span_cost(span)

                    # Prefer one-match full-span explanations such as dictionary/repeat/sequence/date.
                    for m in rz.get("sequence", []):
                        loc = _match_span_indices(m, len(span))
                        if loc == (0, len(span)):
                            pattern = m.get("pattern", "match")
                            if pattern != "bruteforce":
                                cost = zxcvbn_match_cost(m)
                                if cost + STABLE_ZXCVBN_KEEP_MARGIN_LOG10 < brute:
                                    candidates.append((len(span), cost, f"stable_zxcvbn:{pattern}", span))

                    # Also allow zxcvbn's whole-substring estimate when it is materially below brute force.
                    # This catches cases where zxcvbn explains the substring with several internal pieces.
                    whole_cost = safe_log10(float(rz.get("guesses", 0)))
                    if whole_cost + STABLE_ZXCVBN_KEEP_MARGIN_LOG10 < brute:
                        candidates.append((len(span), whole_cost, "stable_zxcvbn:whole_substring", span))

                    # Keep only the cheapest candidate for this exact span.
                    if candidates:
                        best = min(candidates, key=lambda x: x[1])
                        _zxcvbn_span_cache[span] = [best]
                    else:
                        _zxcvbn_span_cache[span] = []
                except Exception:
                    _zxcvbn_span_cache[span] = []

            for end_rel, cost, label, token in _zxcvbn_span_cache.get(span, []):
                if end_rel == len(span):
                    out.append((i, j, cost, label, token))

    return out

def interval_patched_score(password: str, zx: Dict[str, Any], aho_matches: List[AhoMatch]) -> Dict[str, Any]:
    n = len(password)
    by_start: Dict[int, List[Tuple[int, float, str, str]]] = {}

    def add_candidate(i: int, j: int, cost: float, label: str, token: str):
        if not (0 <= i < j <= n):
            return
        if not math.isfinite(cost):
            return
        by_start.setdefault(i, []).append((j, float(cost), label, token))

    # zxcvbn's own full-string sequence is still useful, but it is not the whole candidate universe.
    for m in zx.get("sequence", []):
        loc = _match_span_indices(m, n)
        if loc is not None:
            i, j = loc
            token = password[i:j]
            cost = zxcvbn_match_cost(m)
            label = f"zxcvbn:{m.get('pattern', 'match')}"
            add_candidate(i, j, cost, label, token)

    # Explicit Aho/bad-substring intervals.
    for m in aho_matches:
        add_candidate(m.start, m.end, m.log10_span_cost, f"aho:{m.family}", m.matched_text)

    # Stable substring intervals. This is the important fix: dictionary chunks should not appear
    # or disappear just because an unrelated suffix changed zxcvbn's full-password sequence.
    stable_count = 0
    for i, j, cost, label, token in stable_zxcvbn_substring_candidates(password):
        add_candidate(i, j, cost, label, token)
        stable_count += 1

    # Markov-ish alphabetic intervals. These are generated directly, not borrowed from zxcvbn.
    for i in range(n):
        for j in range(i + 4, min(n, i + 32) + 1):
            span = password[i:j]
            if re.fullmatch(r"[A-Za-z]+", span):
                cost = markovish_alpha_cost(span)
                if cost < brute_span_cost(span):
                    add_candidate(i, j, cost, "markov_alpha", span)

    # Deduplicate exact same end/label/token candidates at each start, keeping the cheapest.
    for i, cand in list(by_start.items()):
        best: Dict[Tuple[int, str, str], Tuple[int, float, str, str]] = {}
        for j, cost, label, token in cand:
            key = (j, label, token)
            old = best.get(key)
            if old is None or cost < old[1]:
                best[key] = (j, cost, label, token)
        by_start[i] = sorted(best.values(), key=lambda x: (x[0], x[1], x[2]))

    dp = [float("inf")] * (n + 1)
    prev = [None] * (n + 1)
    dp[0] = 0.0

    for i in range(n):
        if dp[i] == float("inf"):
            continue

        c = brute_char_cost(password[i])
        if dp[i] + c < dp[i + 1]:
            dp[i + 1] = dp[i] + c
            prev[i + 1] = (i, i + 1, c, "brute_char", password[i])

        for j, cost, label, token in by_start.get(i, []):
            if dp[i] + cost < dp[j]:
                dp[j] = dp[i] + cost
                prev[j] = (i, j, cost, label, token)

    parts = []
    k = n
    while k > 0 and prev[k] is not None:
        i, j, cost, label, token = prev[k]
        parts.append({"start": i, "end": j, "token": token, "label": label, "cost": cost})
        k = i
    parts.reverse()

    return {
        "patched_log10": dp[n],
        "penalty": max(0.0, zx["guesses_log10_float"] - dp[n]),
        "parse": parts,
        "stable_substring_candidates": stable_count,
    }

def stage0_analyze(password: str) -> Dict[str, Any]:
    zx = zxcvbn_score(password)
    aho_matches = BAD_MATCHER.find(password)
    patch = interval_patched_score(password, zx, aho_matches)

    reject_reasons = []
    flags = []

    exact_found, exact_count, exact_status = pwned_count(password)
    pwn_exact = {"found": exact_found, "count": exact_count, "status": exact_status}

    pwn_variants = []
    for name, var, changed in generate_pwn_variants(password):
        f, c, st = pwned_count(var)
        auto_allowed = (changed <= VARIANT_PWN_CHANGED_LEN_REJECT_CUTOFF)
        pwn_variants.append({
            "variant_type": name,
            "variant": var,
            "found": f,
            "count": c,
            "status": st,
            "changed_len": changed,
            "auto_reject_allowed": auto_allowed,
        })

    if len(password) < 8:
        reject_reasons.append("length < 8")

    if pwn_exact["found"]:
        reject_reasons.append(f"exact password appears in pwned-password data count={pwn_exact['count']}")

    for v in pwn_variants:
        if v["found"]:
            if v["auto_reject_allowed"]:
                reject_reasons.append(
                    f"normalized/base variant appears pwned and changed_len <= {VARIANT_PWN_CHANGED_LEN_REJECT_CUTOFF}: "
                    f"{v['variant_type']}={v['variant']!r}, count={v['count']}, changed_len={v['changed_len']}"
                )
            else:
                flags.append(
                    f"pwned base/variant found but not auto-rejected because changed_len={v['changed_len']} > "
                    f"{VARIANT_PWN_CHANGED_LEN_REJECT_CUTOFF}: {v['variant_type']}={v['variant']!r}, count={v['count']}"
                )

    if zx["guesses_log10_float"] < STAGE0_REJECT_ZXCVBN_LOG10:
        reject_reasons.append(f"zxcvbn log10 {zx['guesses_log10_float']:.2f} < {STAGE0_REJECT_ZXCVBN_LOG10}")

    if patch["patched_log10"] < STAGE0_REJECT_PATCHED_LOG10:
        reject_reasons.append(f"patched Stage 0 log10 {patch['patched_log10']:.2f} < {STAGE0_REJECT_PATCHED_LOG10}")

    if aho_matches:
        flags.append(f"Aho bad-substring matches found: {len(aho_matches)}")

    return {
        "password": password,
        "rejected": bool(reject_reasons),
        "reject_reasons": reject_reasons,
        "flags": flags,
        "zxcvbn_score": zx.get("score"),
        "zxcvbn_log10": zx["guesses_log10_float"],
        "patched_zxcvbn_log10": patch["patched_log10"],
        "markov_aho_penalty": patch["penalty"],
        "patch_parse": patch["parse"],
        "stable_substring_candidates": patch.get("stable_substring_candidates", 0),
        "aho_matches": [m.__dict__ for m in aho_matches],
        "pwn_exact": pwn_exact,
        "pwn_variants": pwn_variants,
    }

def stage0_prefix_cost(prefix: str) -> Dict[str, Any]:
    zx = zxcvbn_score(prefix)
    aho = BAD_MATCHER.find(prefix)
    patch = interval_patched_score(prefix, zx, aho)
    return {
        "prefix": prefix,
        "zxcvbn_log10": zx["guesses_log10_float"],
        "patched_log10": patch["patched_log10"],
        "patch_parse": patch["parse"],
        "stable_substring_candidates": patch.get("stable_substring_candidates", 0),
        "aho_matches": [m.__dict__ for m in aho],
    }

print("Stage 0 ready.")

# %%
@dataclass
class ModelBundle:
    model_id: str
    tokenizer: Any
    model: Any
    token_ids_by_first_char: Dict[str, List[Tuple[int, str]]]

@dataclass(frozen=True)
class PathState:
    tokens: Tuple[int, ...]
    logprob: float

@dataclass
class DPScoreResult:
    log10_cost: float
    logprob_ln: float
    num_states_expanded: int
    num_final_paths: int
    num_pruned_paths: int
    truncated: bool
    elapsed_sec: float
    note: str = ""


def logsumexp(vals: List[float]) -> float:
    vals = list(vals)
    if not vals:
        return float("-inf")
    m = max(vals)
    if m == float("-inf"):
        return m
    return m + math.log(sum(math.exp(v - m) for v in vals))


def clear_torch_memory():
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        try:
            torch.cuda.ipc_collect()
        except Exception:
            pass


def build_token_index(tokenizer) -> Dict[str, List[Tuple[int, str]]]:
    """Same speed trick as Experiment 1: only consider tokens whose decoded piece starts with target[i]."""
    special = set(getattr(tokenizer, "all_special_ids", []) or [])
    by_first: Dict[str, List[Tuple[int, str]]] = {}
    for tid in range(len(tokenizer)):
        if tid in special:
            continue
        try:
            piece = tokenizer.decode([tid], skip_special_tokens=False, clean_up_tokenization_spaces=False)
        except Exception:
            continue
        if piece:
            by_first.setdefault(piece[0], []).append((tid, piece))
    return by_first


def load_bundle(model_id: str) -> ModelBundle:
    print(f"Loading model: {model_id}")
    t0 = time.perf_counter()
    tok = AutoTokenizer.from_pretrained(model_id, use_fast=True, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    if tok.pad_token_id is None:
        tok.pad_token_id = tok.eos_token_id
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto" if torch.cuda.is_available() else None,
        trust_remote_code=True,
    )
    if not torch.cuda.is_available():
        model.to("cpu")
    model.eval()
    print("Building token decode index...")
    by_first = build_token_index(tok)
    print(f"Loaded {model_id} in {time.perf_counter() - t0:.1f}s")
    return ModelBundle(model_id=model_id, tokenizer=tok, model=model, token_ids_by_first_char=by_first)


def unload_bundle(bundle: ModelBundle):
    del bundle.model
    del bundle.tokenizer
    clear_torch_memory()


def valid_tokens_for_suffix(bundle: ModelBundle, suffix: str) -> List[Tuple[int, str]]:
    if not suffix:
        return []
    cands = bundle.token_ids_by_first_char.get(suffix[0], [])
    return [(tid, piece) for tid, piece in cands if len(piece) <= len(suffix) and suffix.startswith(piece)]


@torch.no_grad()
def batch_next_logprobs(bundle: ModelBundle, prompt_ids: List[int], states: List[PathState], batch_size: int = BATCH_STATES):
    tokenizer, model = bundle.tokenizer, bundle.model
    model_device = next(model.parameters()).device
    pad_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id

    for start in range(0, len(states), batch_size):
        batch_states = states[start:start + batch_size]
        seqs = [prompt_ids + list(st.tokens) for st in batch_states]
        max_len = max(len(x) for x in seqs)
        input_ids = []
        attention_mask = []
        for seq in seqs:
            pad_len = max_len - len(seq)
            input_ids.append(seq + [pad_id] * pad_len)
            attention_mask.append([1] * len(seq) + [0] * pad_len)

        input_ids_t = torch.tensor(input_ids, dtype=torch.long, device=model_device)
        attention_mask_t = torch.tensor(attention_mask, dtype=torch.long, device=model_device)
        logits = model(input_ids=input_ids_t, attention_mask=attention_mask_t).logits
        last_pos = attention_mask_t.sum(dim=1) - 1
        batch_idx = torch.arange(len(batch_states), device=model_device)
        log_probs = torch.log_softmax(logits[batch_idx, last_pos, :], dim=-1)

        for bi, st in enumerate(batch_states):
            yield st, log_probs[bi]

        del input_ids_t, attention_mask_t, logits, log_probs


@torch.no_grad()
def score_exact_target_dp(
    bundle: ModelBundle,
    prompt: str,
    target: str,
    beam_per_index: int = BEAM_PER_INDEX,
    max_valid_tokens_per_state: int = MAX_VALID_TOKENS_PER_STATE,
    batch_states: int = BATCH_STATES,
) -> DPScoreResult:
    """Experiment-1-style exact token DP over the raw target string.

    This is one DP over target character indices. It is not a loop over possible password splits.
    """
    t0 = time.perf_counter()
    target = str(target)
    if target == "":
        return DPScoreResult(0.0, 0.0, 0, 1, 0, False, 0.0, "empty target")

    prompt_ids = bundle.tokenizer.encode(prompt, add_special_tokens=False)
    n = len(target)
    dp: Dict[int, List[PathState]] = {0: [PathState(tokens=tuple(), logprob=0.0)]}
    valid_cache: Dict[int, List[Tuple[int, str]]] = {}
    num_states_expanded = 0
    num_pruned_paths = 0
    no_valid_at: List[int] = []

    for i in range(n + 1):
        states = dp.get(i, [])
        if not states:
            continue

        if beam_per_index is not None and len(states) > beam_per_index:
            states = sorted(states, key=lambda st: st.logprob, reverse=True)
            num_pruned_paths += len(states) - beam_per_index
            states = states[:beam_per_index]
            dp[i] = states

        if i == n:
            continue

        if i not in valid_cache:
            valid_cache[i] = valid_tokens_for_suffix(bundle, target[i:])
        valid = valid_cache[i]
        if not valid:
            no_valid_at.append(i)
            continue

        device = next(bundle.model.parameters()).device
        valid_ids = torch.tensor([tid for tid, _ in valid], dtype=torch.long, device=device)

        for st, lp_vec in batch_next_logprobs(bundle, prompt_ids, states, batch_size=batch_states):
            num_states_expanded += 1
            vals = lp_vec.index_select(0, valid_ids)
            k = min(max_valid_tokens_per_state, vals.numel())
            top_vals, top_pos = torch.topk(vals, k=k)
            top_vals = top_vals.detach().cpu().tolist()
            top_pos = top_pos.detach().cpu().tolist()
            for logp_token, pos in zip(top_vals, top_pos):
                tid, piece = valid[pos]
                j = i + len(piece)
                dp.setdefault(j, []).append(PathState(tokens=st.tokens + (int(tid),), logprob=st.logprob + float(logp_token)))

    finished = dp.get(n, [])
    if beam_per_index is not None and len(finished) > beam_per_index:
        finished = sorted(finished, key=lambda st: st.logprob, reverse=True)
        num_pruned_paths += len(finished) - beam_per_index
        finished = finished[:beam_per_index]

    total_lp = logsumexp([st.logprob for st in finished])
    cost = float("inf") if total_lp == float("-inf") else -total_lp / math.log(10)
    note = "ok" if math.isfinite(cost) else "no_finished_path"
    if no_valid_at:
        note += "; no_valid_at=" + ",".join(map(str, no_valid_at[:20]))

    return DPScoreResult(
        log10_cost=cost,
        logprob_ln=total_lp,
        num_states_expanded=num_states_expanded,
        num_final_paths=len(finished),
        num_pruned_paths=num_pruned_paths,
        truncated=bool(num_pruned_paths > 0),
        elapsed_sec=time.perf_counter() - t0,
        note=note,
    )

print("Experiment-1-style raw token DP scorer ready.")

# %%
# Re-run this cell to try new passwords.

ans = input("Allow optional 7B escalation if needed? This usually needs Colab Pro + A100. [y/N]: ").strip().lower()
ALLOW_7B_ESCALATION = ans in {"y", "yes"}

print(f"\nEnter up to {MAX_PASSWORDS} raw passwords, one per line.")
print("No split markers. Each DP stage scores one exact raw target string.")
print("Blank line ends input.")
print("Example: DragonCoffee136!")
print("Do not enter real passwords you currently use.\n")

items = []
seen = set()
while len(items) < MAX_PASSWORDS:
    password = input(f"password {len(items)+1}/{MAX_PASSWORDS}: ")
    if password == "":
        break
    if password in seen:
        print("  skipped: duplicate input.")
        continue
    seen.add(password)
    items.append({"password": password})

if not items:
    raise ValueError("No password inputs provided.")

print("\nQueued:")
for i, x in enumerate(items, 1):
    print(f"{i}. {x['password']!r}")

@dataclass
class StageResult:
    stage_name: str
    model_id: str
    template_id: str
    auto_prefix_chars: int
    prefix: str
    target: str
    prefix_cost: float
    llm_target_cost: float
    whole_score: float
    decision: str
    num_states_expanded: int
    num_final_paths: int
    num_pruned_paths: int
    truncated: bool
    elapsed_sec: float
    note: str = ""


def automatic_prefix_and_target(password: str) -> Tuple[str, str]:
    k = max(0, min(AUTO_PREFIX_CHARS, len(password)))
    return password[:k], password[k:]


def run_stage_for_items(active_items, bundle: ModelBundle, template_id: str, is_final_stage=False):
    template_fn = TEMPLATES[template_id]
    still_active = []

    for item in tqdm(active_items, desc=f"{bundle.model_id} {template_id}"):
        password = item["password"]
        prefix, target = automatic_prefix_and_target(password)
        prefix_cost = 0.0 if prefix == "" else stage0_prefix_cost(prefix)["patched_log10"]
        prompt = template_fn(prefix)
        dp = score_exact_target_dp(bundle, prompt, target)
        whole = prefix_cost + dp.log10_cost

        if is_final_stage:
            if whole < DP_REJECT_LOG10:
                decision = f"REJECT: final raw DP score {whole:.2f} < {DP_REJECT_LOG10}"
                item["final_verdict"] = "REJECT"
                item["final_reason"] = decision
            else:
                decision = f"ACCEPT: final raw DP score {whole:.2f} >= {DP_REJECT_LOG10}"
                item["final_verdict"] = "ACCEPT"
                item["final_reason"] = decision
        else:
            if whole < DP_REJECT_LOG10:
                decision = f"REJECT: raw DP score {whole:.2f} < {DP_REJECT_LOG10}"
                item["final_verdict"] = "REJECT"
                item["final_reason"] = decision
            elif whole > DP_ACCEPT_LOG10:
                decision = f"ACCEPT: raw DP score {whole:.2f} > {DP_ACCEPT_LOG10}"
                item["final_verdict"] = "ACCEPT"
                item["final_reason"] = decision
            else:
                decision = f"ESCALATE: {DP_REJECT_LOG10} <= raw DP score {whole:.2f} <= {DP_ACCEPT_LOG10}"
                still_active.append(item)

        item["dp_stages"].append(StageResult(
            stage_name=f"{bundle.model_id} / {template_id}",
            model_id=bundle.model_id,
            template_id=template_id,
            auto_prefix_chars=AUTO_PREFIX_CHARS,
            prefix=prefix,
            target=target,
            prefix_cost=prefix_cost,
            llm_target_cost=dp.log10_cost,
            whole_score=whole,
            decision=decision,
            num_states_expanded=dp.num_states_expanded,
            num_final_paths=dp.num_final_paths,
            num_pruned_paths=dp.num_pruned_paths,
            truncated=dp.truncated,
            elapsed_sec=dp.elapsed_sec,
            note=dp.note,
        ))

    return still_active


t0_all = time.perf_counter()

print("\nRunning Stage 0...")
records = []
for x in tqdm(items, desc="Stage 0"):
    st0 = stage0_analyze(x["password"])
    rec = {
        **x,
        "stage0": st0,
        "dp_stages": [],
        "final_verdict": "REJECT" if st0["rejected"] else "PENDING",
        "final_reason": "; ".join(st0["reject_reasons"]) if st0["rejected"] else "",
    }
    records.append(rec)

active = [r for r in records if r["final_verdict"] == "PENDING"]

if active:
    qwen = load_bundle(QWEN_15B_MODEL_ID)

    active = run_stage_for_items(
        active, qwen,
        "A0_current_vulnerable",
        is_final_stage=False,
    )

    if active:
        active = run_stage_for_items(
            active, qwen,
            "C3_task_continue_field",
            is_final_stage=(not ALLOW_7B_ESCALATION),
        )

    unload_bundle(qwen)

if ALLOW_7B_ESCALATION and active:
    seven = load_bundle(SEVEN_B_MODEL_ID)

    active = run_stage_for_items(
        active, seven,
        "A0_current_vulnerable",
        is_final_stage=False,
    )

    if active:
        active = run_stage_for_items(
            active, seven,
            "C3_task_continue_field",
            is_final_stage=True,
        )

    unload_bundle(seven)

for r in active:
    if r["final_verdict"] == "PENDING":
        r["final_verdict"] = "ACCEPT"
        r["final_reason"] = "no rejecting stage fired"

print(f"\nRouter finished in {time.perf_counter() - t0_all:.1f}s")
for r in records:
    print(f"{r['final_verdict']} - {r['password']} - {r['final_reason']}")

# %%
def fmt(x, nd=2):
    try:
        if math.isinf(x):
            return "inf"
        return f"{x:.{nd}f}"
    except Exception:
        return str(x)


def render_report(records):
    lines = []
    now = datetime.datetime.now().isoformat(timespec="seconds")
    lines.append("LLM Password Routing Demo Report")
    lines.append("=" * 80)
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("Configuration")
    lines.append("-" * 80)
    lines.append(f"1.5B model: {QWEN_15B_MODEL_ID}")
    lines.append(f"7B escalation allowed: {ALLOW_7B_ESCALATION}")
    if ALLOW_7B_ESCALATION:
        lines.append(f"7B model: {SEVEN_B_MODEL_ID}")
    lines.append("Input format: one raw password per line")
    lines.append("DP method: Experiment-1-style exact token DP over one raw target string")
    lines.append("No user-provided separators and no loop over all possible split positions")
    lines.append(f"Automatic prefix chars before target: {AUTO_PREFIX_CHARS}")
    lines.append(f"DP reject threshold: whole_score < {DP_REJECT_LOG10}")
    lines.append(f"DP early accept threshold: whole_score > {DP_ACCEPT_LOG10}")
    lines.append(f"Stage 0 zxcvbn reject cutoff: {STAGE0_REJECT_ZXCVBN_LOG10}")
    lines.append(f"Stage 0 patched reject cutoff: {STAGE0_REJECT_PATCHED_LOG10}")
    lines.append(f"Aho bad-substring patterns loaded: {BAD_MATCHER.num_patterns}")
    lines.append(f"Stable zxcvbn substring length range: {STABLE_ZXCVBN_SUBSTRING_MIN_LEN}..{STABLE_ZXCVBN_SUBSTRING_MAX_LEN}")
    lines.append(f"Stable zxcvbn max substring calls per password: {STABLE_ZXCVBN_MAX_SUBSTRING_CALLS}")
    lines.append("")

    for idx, r in enumerate(records, 1):
        st0 = r["stage0"]
        lines.append("=" * 80)
        lines.append(f"Password {idx}: {r['password']!r}")
        lines.append(f"Final verdict: {r['final_verdict']}")
        lines.append(f"Final reason: {r['final_reason']}")
        lines.append("")

        lines.append("Stage 0 on whole password")
        lines.append("-" * 80)
        lines.append(f"zxcvbn score: {st0['zxcvbn_score']}")
        lines.append(f"zxcvbn guesses_log10: {fmt(st0['zxcvbn_log10'])}")
        lines.append(f"patched Stage 0 log10: {fmt(st0['patched_zxcvbn_log10'])}")
        lines.append(f"Markov/Aho penalty vs zxcvbn: {fmt(st0['markov_aho_penalty'])}")
        lines.append(f"stable zxcvbn substring candidates added: {st0.get('stable_substring_candidates', 0)}")

        if st0["flags"]:
            lines.append("flags:")
            for fl in st0["flags"]:
                lines.append(f"  - {fl}")

        pe = st0["pwn_exact"]
        lines.append(f"pwned exact: {'YES' if pe['found'] else 'no'} (count={pe['count']}, status={pe['status']})")
        hits = [v for v in st0["pwn_variants"] if v["found"]]
        if hits:
            lines.append("pwned normalized/base variants:")
            for v in hits[:8]:
                lines.append(
                    f"  - {v['variant_type']}: {v['variant']!r} count={v['count']} "
                    f"changed_len={v['changed_len']} auto_reject_allowed={v['auto_reject_allowed']}"
                )
        else:
            lines.append("pwned normalized/base variants: none found")

        if st0["aho_matches"]:
            lines.append("Aho matches:")
            for m in st0["aho_matches"][:10]:
                lines.append(
                    f"  - [{m['start']}:{m['end']}] {m['matched_text']!r} "
                    f"family={m['family']} cost={m['log10_span_cost']} action={m['action']}"
                )

        lines.append("patched Stage 0 parse:")
        for part in st0["patch_parse"][:20]:
            lines.append(
                f"  - [{part['start']}:{part['end']}] {part['token']!r} "
                f"{part['label']} cost={fmt(part['cost'])}"
            )

        if st0["rejected"]:
            lines.append("Stage 0 decision: REJECT")
            for rr in st0["reject_reasons"]:
                lines.append(f"  - {rr}")
            lines.append("")
            continue
        else:
            lines.append("Stage 0 decision: no reject; use raw token DP")
            lines.append("")

        lines.append("DP escalation trace")
        lines.append("-" * 80)
        if not r["dp_stages"]:
            lines.append("No DP stages run.")
            lines.append("")
            continue

        for sidx, s in enumerate(r["dp_stages"], 1):
            lines.append(f"DP stage {sidx}: {s.stage_name}")
            lines.append(f"template: {s.template_id}")
            lines.append(f"automatic prefix chars: {s.auto_prefix_chars}")
            lines.append(f"prefix given in prompt: {s.prefix!r}")
            lines.append(f"exact target scored by token DP: {s.target!r}")
            lines.append(f"prefix Stage 0 cost: {fmt(s.prefix_cost)}")
            lines.append(f"LLM target cost: {fmt(s.llm_target_cost)}")
            lines.append(f"whole score: {fmt(s.whole_score)}")
            lines.append(f"decision: {s.decision}")
            lines.append(f"states expanded: {s.num_states_expanded}")
            lines.append(f"finished paths: {s.num_final_paths}")
            lines.append(f"pruned paths: {s.num_pruned_paths}")
            lines.append(f"truncated: {s.truncated}")
            lines.append(f"elapsed: {fmt(s.elapsed_sec)}s")
            if s.note:
                lines.append(f"note: {s.note}")
            lines.append("")

    return "\n".join(lines)


report = render_report(records)
report_path = "llm_password_routing_report.txt"
json_path = "llm_password_routing_records.json"

with open(report_path, "w", encoding="utf-8") as f:
    f.write(report)


def stage_to_dict(s: StageResult):
    return {
        "stage_name": s.stage_name,
        "model_id": s.model_id,
        "template_id": s.template_id,
        "auto_prefix_chars": s.auto_prefix_chars,
        "prefix": s.prefix,
        "target": s.target,
        "prefix_cost": s.prefix_cost,
        "llm_target_cost": s.llm_target_cost,
        "whole_score": s.whole_score,
        "decision": s.decision,
        "num_states_expanded": s.num_states_expanded,
        "num_final_paths": s.num_final_paths,
        "num_pruned_paths": s.num_pruned_paths,
        "truncated": s.truncated,
        "elapsed_sec": s.elapsed_sec,
        "note": s.note,
    }


json_records = []
for r in records:
    d = dict(r)
    d["dp_stages"] = [stage_to_dict(s) for s in r["dp_stages"]]
    json_records.append(d)

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(json_records, f, indent=2)

print(report)
print("\nSaved report:", report_path)
print("Saved JSON:", json_path)

try:
    from google.colab import files
    files.download(report_path)
except Exception:
    pass
