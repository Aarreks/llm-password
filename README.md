# LLM Password Router Demo

This repository contains the final demo notebook for the ECE 202C password-security project.
The goal is to route password candidates through a cheap reject-only Stage 0 and, only when needed,
an exact token-DP semantic check using small instruction-tuned language models.

## Main notebook

Open:

```text
notebooks/final_password_router_demo.ipynb
```

The notebook expects one raw password per line. Do not add split markers. Each DP stage scores one exact raw target string.

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

## What is included

```text
notebooks/final_password_router_demo.ipynb       final Colab notebook
notebooks/archive/experiment1d_reference_32_32_32.ipynb   reference Experiment 1 notebook
src/password_router_demo.py                      code extracted from the final notebook
data/stage0_bad_substrings.csv                   Stage 0 Aho-Corasick resource (21,555 patterns)
scripts/generate_stage0_bad_substrings.py        data generator
results/                                         selected final-run reports
requirements.txt                                 Python dependencies
```

## What is intentionally excluded

Earlier toy architecture notebooks, fake tests, and the slow split-scan branch are excluded. The slow split scan measured suffix-only continuation scores and was not the final router metric.

## Running in Colab

1. Upload or clone this repository in Colab.
2. Run `notebooks/final_password_router_demo.ipynb` from the repository root so it can find `data/stage0_bad_substrings.csv`.
3. The 1.5B model path is the practical default. Optional 7B escalation usually needs a stronger GPU.
4. Do not enter real passwords you currently use.

## Notes on the score

The LLM-DP score is a model-and-prompt-specific prefix log10 cost. It is not a literal real-world crack-time estimate. It estimates how much probability mass the tested model assigns to generating the exact password string as the next output prefix, using bounded Experiment-1-style path-sum DP.
