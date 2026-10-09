# Benchmarks

Performance is measured, not promised, and it lives beside accuracy: the same
`cargo xtask eval` run that scores the labeled corpus also times every tool
(cudabom, blint, Syft, Trivy), capturing wall time and peak RSS. Each figure
sits next to the outcome that run produced, because a low number next to
"0 findings" means the tool had little to do, not that it was efficient.

See the performance section of [`comparison.md`](comparison.md), regenerated with:

```
cargo xtask eval --download --write-comparison --container-image <ref>
```

Lower cost is better only when the outcome is equal; figures reflect the host
and corpus of the run and are indicative, not a controlled microbenchmark.
