# Plexar comparison benchmark

Reproducible, apples-to-apples comparison of **Trivy**, **Grype**, **Kubescape**
and **Plexar** on the *same* set of container images, designed to run on an
air-gapped **CRI-O** Kubernetes node (e.g. an on-prem appliance).

## What this proves (and what it doesn't)

- Trivy and Grype are raw image scanners. Plexar **ingests the same finding
  set** (it wraps Trivy) and then reduces it with context. So the honest story
  is **not** "Plexar finds fewer CVEs" — it's *"the same findings, made
  actionable"*. `analyze.py` prints the reduction **funnel** rather than a
  single hero number, so every stage (fixable → reachable → in-use) is visible
  and defensible.
- Kubescape is misconfiguration/posture focused; it is reported separately and
  is **not** compared on raw CVE counts.
- No number is invented. A tool only appears if its output is present.

## Prerequisites on the node (air-gapped)

You must pre-seed every scanner's database because the harness runs fully
offline. On an internet-connected host, then copy onto the target node:

```bash
# Trivy DB  -> ~/.cache/trivy  (or set TRIVY_CACHE_DIR)
trivy image --download-db-only

# Grype DB  -> ~/.cache/grype  (or set GRYPE_DB_CACHE_DIR)
grype db update

# Kubescape artifacts -> ~/.kubescape
kubescape download artifacts
```

Also required on the node: `crictl`, `skopeo`, and the `plexar` binary
(`plexar-linux`). The node already has CRI-O at `/run/crio/crio.sock`.

## Run it

```bash
# copy the harness + binaries to the node
scp bench/compare.sh bench/analyze.py plexar-linux root@<node>:/root/bench/

# on the node (root):
cd /root/bench
NAMESPACES="app-tier data-tier gateway" PLEXAR=./plexar-linux ./compare.sh
#   or scan every image the node holds:
IMAGES_FROM=crictl PLEXAR=./plexar-linux ./compare.sh
```

Outputs land in `./bench-results/`:

```
bench-results/
  versions.txt        # tool versions + node info (reproducibility)
  images.txt          # exact image set scanned
  trivy/<img>.json    # per-image Trivy output
  grype/<img>.json    # per-image Grype output
  kubescape.json      # Kubescape posture scan
  plexar.json         # Plexar scan (captures allCVEs + blast + in-use)
  *.err               # per-tool stderr, if any
```

## Analyze (off the node)

```bash
scp -r root@<node>:/root/bench/bench-results ./
python3 bench/analyze.py bench-results/ > bench-results/comparison.md
```

`comparison.md` contains the raw-scanner table, the Kubescape summary, and the
Plexar reduction funnel — paste-ready into `bench/article-draft.md`.

## Fairness notes

- All tools scan the **identical** CRI-O tarball per image (no re-pull, no DB
  drift between tools).
- Same severity filter for Trivy (`--severity CRITICAL,HIGH,MEDIUM`); Grype
  reports all severities and `analyze.py` normalises them.
- Run Plexar over the **same namespaces** used for image discovery so its pod
  set matches the scanned image set.
- Record `versions.txt` in any published result. DB snapshot dates matter:
  different DB versions => different counts, independent of the tools.
