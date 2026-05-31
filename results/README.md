# Selected results

These are the most presentable result artifacts from the final demo branch.
They are intentionally small; the repo excludes earlier toy-router branches,
slow split-scan outputs, and fake tests.

Included examples:

- `stage0_stable_substring_rejects_report.txt`: stable Stage 0 substring parsing rejects a structured family consistently.
- `random_autoaccept_report.txt`: a random-looking password autoaccepts quickly under the 32.0 threshold.
- `math_structured_accept_report.txt`: a math-flavored password is accepted but not autoaccepted.
- `code_fragment_reject_interactive_run.txt`: a C-style loop is rejected as highly model-predictable.
