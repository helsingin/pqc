# SLH-DSA adapter known-answer fixtures

Extracted from Cloudflare CIRCL v1.6.5 `sign/slhdsa/testdata/sigGen_prompt.json.gz` and `sigGen_results.json.gz`:

- [Input vectors](https://github.com/cloudflare/circl/blob/v1.6.5/sign/slhdsa/testdata/sigGen_prompt.json.gz)
- [Expected results](https://github.com/cloudflare/circl/blob/v1.6.5/sign/slhdsa/testdata/sigGen_results.json.gz)

For each supported parameter set and deterministic/randomized external pure-mode group, select the case with the shortest message. Preserve its private key, message, context and additional randomness. Store SHA-256 of the complete expected signature rather than the much larger signature itself. These are published test keys, never operational keys.

The tests exercise the pqc adapter against existing ACVP fixtures; passing them is not a claim of NIST module validation.

| tcId | Parameter set | Randomized |
|---|---|---|
| 179 | SLH-DSA-SHA2-192s | False |
| 201 | SLH-DSA-SHA2-256s | False |
| 489 | SLH-DSA-SHA2-192s | True |
| 513 | SLH-DSA-SHA2-256s | True |

Upstream compressed-file SHA-256 digests:

- `sigGen_prompt.json.gz`: `f7d2affc3d7202d3904719f8fd1652aafe4ec94adf207f708346d1e03ab3c479`
- `sigGen_results.json.gz`: `85ff569c894b91c9e55359d723d95b4dbac7954bd9356d3e48ad244095ea3979`

Upstream license is retained in [CIRCL-LICENSE](CIRCL-LICENSE).
