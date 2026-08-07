# Retrieval evaluation fixtures

`questions.dataset` remains the RepoLocus self-retrieval smoke test. The versioned
repositories under `repos/` are separate, synthetic codebases used by the release gate;
they are authored for this project, covered by the repository's Apache-2.0 license, and
must never be treated as production examples.

`external-manifest.json` records each fixture revision, origin, license, deterministic
tree digest, and qrel digest. `qrels/*.jsonl` supplies explicit answerable/no-answer truth,
graded source ranges, hard negatives, and `must_not_return` paths. Run the gate with:

```console
uv run python scripts/evaluate_external_repositories.py evaluation
```

The v0.1.5 thresholds are hit rate >= 0.90, macro recall@5 >= 0.80, MRR >= 0.75,
citation recall >= 1.0, no-answer F1 >= 0.80, and zero `must_not_return` violations.
The JSON report records these thresholds, the pass/fail verdict, and per-repository metrics.
