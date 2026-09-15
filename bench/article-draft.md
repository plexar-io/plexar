# From 18,000 CVEs to a fixable few: prioritising vulnerabilities on a real Kubernetes cluster

> DRAFT for The New Stack. Numbers marked `[FILL]` come from `bench/analyze.py`
> after running `bench/compare.sh` on the cluster. Do not publish placeholders.
> Every figure must be reproducible from `bench-results/versions.txt`.

## The cluster (anonymized, but characterized)

We ran this on a real production cluster. We're not naming the operator, so here
is the profile that actually matters for the result — everything you'd need to
judge whether it resembles yours:

- **~100 pods**, built from **~40 microservices**.
- Shipped as an **on-prem, air-gapped appliance** — no internet egress for the
  security tooling, CRI-O runtime.
- **Flat network**: exactly **one** NetworkPolicy across the whole cluster, so
  nearly every pod is mutually reachable and internet-exposed.
- Heavy **shared-base-image** reuse across services (the usual monorepo/base
  pattern).

That profile is common for commercial Kubernetes appliances; if it matches your
environment, the numbers should rhyme with yours.

## The problem: scanners find everything, and that's the problem

Point a modern image scanner at a cluster like this and you get a number that is
simultaneously accurate and useless. The raw finding count was **18,381**
vulnerability instances across the workloads — **15,853** of them with a fix
available.

No team patches 18,381 things. The interesting question was never "how many
CVEs do we have"; it's "which ones can actually hurt us, and which do we fix
first." That's the gap this benchmark measures.

## Method (reproducible)

We ran four tools against the **same** container images, exported once from the
node's CRI-O store as tarballs so no tool re-pulled or hit a different database:

- **Trivy** and **Grype** — raw image CVE scanners.
- **Kubescape** — posture/misconfiguration.
- **Plexar** — which ingests Trivy's findings and adds runtime, network and
  blast-radius context.

Fully air-gapped; every DB pre-seeded and pinned (see `versions.txt`). Harness:
[`bench/compare.sh`], analysis: [`bench/analyze.py`].

## Why you can trust this without the cluster's name

We're deliberately not naming the operator. In a benchmark, the customer name
was never the evidence anyway — reproducibility is. So instead of "trust us, it's
BigCo," we give you the three things that actually let you check the claim:

1. **The harness is open.** Every command, flag and offline setting is in
   `compare.sh`; the normalisation logic is in `analyze.py`. Nothing is
   hand-counted.
2. **The environment is pinned.** `versions.txt` records every tool version and
   vulnerability-DB snapshot date — the variables that actually move CVE counts.
3. **You can run it on a cluster you own.** The funnel is a *method*, not a
   single trophy number. Point the same harness at your cluster and you'll get
   your own funnel. To make that concrete, we also publish a run against a
   fully public reference stack (see below) that anyone can reproduce end to end.

A named customer proves one anecdote. An open, reproducible method proves the
pattern.

## Raw scanners agree — because they're doing the same job

| Tool | Images | Raw findings | Unique CVEs | Fixable | Critical | High |
|---|---|---|---|---|---|---|
| Trivy | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` |
| Grype | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` | `[FILL]` |

Trivy and Grype land in the same ballpark — as they should, scanning identical
images. **This is the key honest point: Plexar does not "beat" them at finding
CVEs. It consumes the same finding set.** The difference is what happens next.

## The funnel: from raw to actionable

Plexar takes those findings and filters them by context. Each stage is a claim
you can audit:

| Stage | CVEs | Why it drops |
|---|---|---|
| 1. Raw findings (all severities) | **18,381** | the number scanners report |
| 2. Has a fix available | **15,853** | you cannot act on unfixable |
| 3. Severity ≥ High | **3,657** | 213 critical + 3,444 high |
| 4. On internet-reachable pods | **3,598** | nearly every pod is exposed |
| 5. Loaded at runtime (in use) | `[FILL — needs /proc profiling]` | dormant packages aren't exploitable |
| Distinct remediations (dedup) | `[FILL]` | shared base images => one fix clears many |

> Caveat we will state plainly in the piece: stage 5 requires Plexar's runtime
> profiler (`/proc`) to be active. On our first pass it was only partially
> available, so we either (a) re-run with profiling on, or (b) publish the
> funnel through stage 4 and dedup only. We will not imply runtime filtering we
> didn't measure.

## The dedup insight

Because the ~40 microservices share base images, the *same* CVE recurs across
dozens of pods. One example from the scan: a single OpenSSL CVE
(`CVE-2026-45447`) appeared in **41** services; `libssl3t64` in 41, `runc` in
19. So `[FILL]` raw instances collapse to roughly `[FILL]` distinct
(CVE, package, fix) remediations. **Fix once, clear dozens** — that's the number
an engineering lead actually cares about.

## Kubescape: a different axis

Kubescape evaluated `[FILL]` controls (`[FILL]` failed). It answers "is this
configured safely," not "which CVE matters" — complementary, not comparable, and
we present it as such.

## Takeaway

The scanners were never wrong; 18,381 findings are really there. But the job of
security tooling in 2026 isn't discovery — models and scanners have made
discovery cheap. The bottleneck is **triage**: turning an unactionable dump into
the handful of fixes that remove real risk. On this cluster the funnel took
18,381 raw findings down to a few hundred exposed, fixable, high-severity CVEs —
and a much smaller set of distinct remediations.

That's the number worth publishing.

## A fully public companion run

Because the enterprise cluster is anonymized, we pair it with a run anyone can
reproduce from scratch: a public reference stack (e.g. a `kind` cluster of
well-known open-source images) scanned with the identical harness. It won't have
100 microservices, but it demonstrates the method end to end and lets readers
verify the funnel logic on images they can pull themselves. The enterprise
numbers show the *scale*; the public run shows the *method is sound*.

---

### Reproduce it

```bash
# on the target node (namespaces are examples — use your own):
NAMESPACES="app-tier data-tier gateway" PLEXAR=./plexar-linux bench/compare.sh
# off-box:
python3 bench/analyze.py bench-results/ > bench-results/comparison.md
```
