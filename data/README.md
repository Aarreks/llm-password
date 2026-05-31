# Stage 0 bad-substring data

`stage0_bad_substrings.csv` contains 21,555 pattern rows plus one header row.
These compact sequence-like substrings are used by the Stage 0 Aho-Corasick matcher.

A match is not an automatic rejection; it is a cheap span explanation used by the
Stage 0 interval parser.

The CSV included here is the full resource used by the presentable demo reports.
`scripts/generate_stage0_bad_substrings.py` is kept as the generator/reference for
how this resource was constructed.
