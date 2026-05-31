# LLM Password Router Demo

This repository contains the final demo code and supporting experiments for an ECE 202C password-security project.

The main idea is a password-checking router: cheap prechecks reject obvious weak passwords, and only borderline cases go to an LLM-based semantic predictability check. The LLM check uses bounded token dynamic programming (DP) to estimate how much probability the model assigns to generating the exact password string as its next output prefix.

## Main demo notebook

Open:

```text
notebooks/final_password_router_demo.ipynb
```

The demo expects one raw password per line. Do not add split markers. Each DP stage scores one exact raw target string.

Final policy used in the presentable demo branch:

```text
Stage 0 zxcvbn reject cutoff:      log10 score < 10
Stage 0 patched reject cutoff:     log10 score < 10
LLM-DP reject cutoff:              whole_score < 20
LLM-DP early accept cutoff:        whole_score > 32
Input format:                      one raw password per line
No split scan:                     true
Automatic prefix chars:            0
```

## Repository layout

```text
notebooks/final_password_router_demo.ipynb
    Final Colab demo notebook.

notebooks/experiments/exp1d_token_dp/experiment1d_token_dp_reference.ipynb
    Reference Experiment 1 notebook for constrained token-DP scoring.

notebooks/experiments/exp2_template_sensitivity/
    Experiment 2 continuation-template sensitivity notebook, template CSV, password CSV, and related inputs.

notebooks/experiments/exp2b_direct_rating_negative_result/
    Negative-result experiment showing why we should not directly ask an LLM whether a password is structured.

src/password_router_demo.py
    Python code extracted from the final demo notebook.

data/stage0_bad_substrings.csv
    Stage 0 Aho-Corasick resource used by the demo notebook.

scripts/generate_stage0_bad_substrings.py
    Reproducibility/provenance script for generating a similar Stage 0 pattern list. The checked-in CSV is the one used by the demo.

results/
    Selected demo reports plus Experiment 2 and Experiment 2B result files.
```

## Included experiments

### Experiment 1: bounded token-DP scoring

The Experiment 1 reference notebook is included because the final router's LLM stage is based on this method. It scores an exact target string with constrained token DP, keeping a bounded number of token paths per character index.

### Experiment 2: prompt/template sensitivity

The continuation-template experiment compares prompt wordings for LLM token-DP scoring. This motivates using continuation-style prompts rather than direct judgment prompts.

### Experiment 2B: negative result for direct LLM rating

The direct JSON-rating experiment is included as a negative result. It tests a tempting deployment shortcut: directly ask an LLM to rate whether a password is structured. The result is less suitable for the final router than token-DP continuation scoring, so the final demo does not use direct ratings as its security decision.

## What is intentionally excluded

Earlier toy architecture notebooks, fake tests, intermediate router branches, and the slow split-scan branch are excluded. The slow split scan measured suffix-only continuation scores and was not the final router metric.

## Running in Colab

1. Upload or clone this repository in Colab.
2. Run `notebooks/final_password_router_demo.ipynb` from the repository root so it can find `data/stage0_bad_substrings.csv`.
3. The 1.5B model path is the practical default. Optional 7B escalation usually needs a stronger GPU.
4. Do not enter real passwords you currently use.

## Notes on the score

The LLM-DP score is a model-and-prompt-specific prefix log10 cost. It is not a literal real-world crack-time estimate. It estimates how much probability mass the tested model assigns to generating the exact password string as the next output prefix, using bounded Experiment-1-style path-sum DP.


## Included experiment results

- `results/exp1d_32-32-32/`: primary Experiment 1D token-DP result set matching the checked-in reference notebook.
- `results/exp1d_512-512-512/`: higher-budget Experiment 1D robustness run.
- `results/exp2_template_sensitivity/`: continuation-template sensitivity results.
- `results/exp2b_direct_rating_negative_result/`: negative result showing that directly asking an LLM to rate password structure is not the final method.


## Experiment 1D input data

The Experiment 1D notebook is bundled with its input CSV at `notebooks/experiments/exp1d_token_dp/exp1_passwords_100.csv`.
