# Experiment 2B: direct JSON rating negative result

This notebook tests direct LLM prompting: ask the model to output a JSON `risk_score` for whether a password is structured.

This is included as a negative result. The final router does not use direct structural ratings as its decision rule. It uses continuation-style token-DP scoring instead, because that gives a more concrete probability-style quantity for the exact password string.
