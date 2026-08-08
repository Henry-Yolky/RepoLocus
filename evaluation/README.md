# Retrieval evaluation fixtures

`questions.dataset` remains the RepoLocus self-retrieval smoke test. The versioned
repositories under `repos/` are separate, synthetic codebases used by the release gate;
they are authored for this project, covered by the repository's Apache-2.0 license, and
must never be treated as production examples.

`external-manifest.json` records each fixture revision, origin, license, deterministic
tree digest, qrel digest, expected count, and versioned coverage minima. The 102 static qrels
form 82 case families and supply explicit answerable/no-answer truth, graded source ranges,
hard negatives, and 33 `must_not_return` cases distributed across every fixture. Each qrel has
a stable case ID and family. `qrels/review-provenance.json` binds the exact reviewed qrel and
fixture-tree digests, plus a canonical-intent ledger for every no-answer family, to their fixture
revisions; the manifest pins that record's digest.
The runner rejects provenance drift, duplicate fixture identities, invalid source or decoy
paths, insufficient family/query-type distribution, and count/hash drift. Run with:

```console
uv run python scripts/evaluate_external_repositories.py evaluation
```

The v0.2 thresholds are hit rate >= 0.90, macro recall@5 >= 0.80, MRR >= 0.75,
citation recall >= 1.0, no-answer F1 >= 0.80, zero duplicate evidence and
`must_not_return` violations, maximum overlapping-line IoU <= 0.79, intent and graph grounding
accuracy >= 1.0, mean path diversity >= 0.50, and semantic-slice hit rate/MRR/no-answer F1 >=
0.50/0.50/0.75. The count gates require at least 60 answerable, 20 no-answer, and 60
citation-bearing cases. The JSON report records these thresholds, the pass/fail verdict,
per-repository/query-type/intent metrics, and deterministic
2,000-resample bootstrap intervals. Resampling clusters first by fixture and then by case
family, so paraphrases are not treated as independent observations. Positive bootstrap gates
use the 95% lower bound; duplicate-evidence and `must_not_return` gates use the upper bound.
Maximum line overlap and per-intent/query-type slices use their observed values.
