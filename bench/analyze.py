#!/usr/bin/env python3
"""
analyze.py — normalise the raw outputs from bench/compare.sh into an
apples-to-apples comparison table + the Plexar reduction funnel.

Stdlib only. Run anywhere (e.g. your laptop) after copying bench-results off
the target node:

    python3 bench/analyze.py bench-results/ > bench-results/comparison.md

Honest-by-design:
  * Trivy and Grype are raw image scanners — they report the same finding set
    Plexar ingests. The comparison is NOT "Plexar finds fewer CVEs"; it is
    "the same findings, made actionable by context (fixable / reachable /
    in-use)". The funnel makes each reduction stage explicit.
  * Numbers are only emitted for tools whose output is actually present. No
    stage is invented.
"""
import json
import os
import sys
import glob
from collections import defaultdict

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]


def load(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"# warn: cannot parse {path}: {e}", file=sys.stderr)
        return None


def norm_sev(s):
    s = (s or "UNKNOWN").upper()
    return s if s in SEV_ORDER else "UNKNOWN"


class Agg:
    """Accumulates findings for one tool in a normalised shape."""
    def __init__(self, name):
        self.name = name
        self.instances = 0                       # raw finding rows
        self.by_sev = defaultdict(int)
        self.fixable = 0
        self.unique_cve = set()                  # id
        self.unique_pair = set()                 # (id, pkg)
        self.images = 0

    def add(self, cve_id, pkg, sev, fixable):
        self.instances += 1
        self.by_sev[norm_sev(sev)] += 1
        if fixable:
            self.fixable += 1
        if cve_id:
            self.unique_cve.add(cve_id)
            self.unique_pair.add((cve_id, pkg or ""))

    def row(self):
        sv = self.by_sev
        return [
            self.name, self.images, self.instances,
            len(self.unique_cve), self.fixable,
            sv["CRITICAL"], sv["HIGH"], sv["MEDIUM"],
        ]


def parse_trivy(results_dir):
    a = Agg("Trivy")
    files = sorted(glob.glob(os.path.join(results_dir, "trivy", "*.json")))
    a.images = len(files)
    for fp in files:
        d = load(fp)
        if not d:
            continue
        for res in (d.get("Results") or []):
            for v in (res.get("Vulnerabilities") or []):
                a.add(v.get("VulnerabilityID"), v.get("PkgName"),
                      v.get("Severity"), bool(v.get("FixedVersion")))
    return a if files else None


def parse_grype(results_dir):
    a = Agg("Grype")
    files = sorted(glob.glob(os.path.join(results_dir, "grype", "*.json")))
    a.images = len(files)
    for fp in files:
        d = load(fp)
        if not d:
            continue
        for m in (d.get("matches") or []):
            vuln = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            fix = vuln.get("fix") or {}
            fixable = fix.get("state") == "fixed" or bool(fix.get("versions"))
            a.add(vuln.get("id"), art.get("name"), vuln.get("severity"), fixable)
    return a if files else None


def parse_kubescape(results_dir):
    """Kubescape is config/posture focused; CVE image data is optional.
    Return a text summary rather than forcing it into the CVE table."""
    fp = os.path.join(results_dir, "kubescape.json")
    d = load(fp)
    if not d:
        return None
    sd = d.get("summaryDetails") or {}
    controls = sd.get("controls") or {}
    failed = sum(1 for c in controls.values() if (c.get("statusInfo") or {}).get("status") == "failed"
                 or c.get("status") == "failed")
    total = len(controls)
    # Some kubescape versions expose resource/vuln counts differently; be lenient.
    score = sd.get("complianceScore") or sd.get("score")
    return {"controls_total": total, "controls_failed": failed, "score": score}


def parse_plexar(results_dir):
    d = load(os.path.join(results_dir, "plexar.json"))
    if not d:
        return None
    scores = d.get("scores") or []
    f = {
        "pods": len(scores),
        "cluster_score": d.get("clusterScore"),
        "netpols": d.get("networkPolicies"),
        "raw": 0, "fixable": 0,
        "critical": 0, "high": 0, "medium": 0,
        "reachable_crit": 0, "reachable_high": 0,
        "has_allcves": 0,
        "inuse_entries": 0, "total_entries": 0,
        "unique_cve": set(), "unique_pair": set(), "unique_fix": set(),
    }
    for s in scores:
        v = s.get("vulns") or {}
        b = s.get("blast") or {}
        f["raw"] += v.get("totalCount", 0)
        f["fixable"] += v.get("fixableCount", 0)
        f["critical"] += v.get("critical", 0)
        f["high"] += v.get("high", 0)
        f["medium"] += v.get("medium", 0)
        if b.get("internetAccess"):
            f["reachable_crit"] += v.get("critical", 0)
            f["reachable_high"] += v.get("high", 0)
        cves = v.get("allCVEs") or []
        if cves:
            f["has_allcves"] += 1
        else:
            cves = v.get("topCVEs") or []
        for c in cves:
            f["total_entries"] += 1
            if c.get("inUse"):
                f["inuse_entries"] += 1
            cid, pkg, fx = c.get("id"), c.get("package"), c.get("fixedVersion")
            if cid:
                f["unique_cve"].add(cid)
                f["unique_pair"].add((cid, pkg or ""))
                if fx:
                    f["unique_fix"].add((cid, pkg or "", fx))
    return f


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        print("usage: analyze.py <bench-results-dir>", file=sys.stderr)
        sys.exit(2)
    rd = sys.argv[1]

    print("# Plexar benchmark — air-gapped CRI-O cluster\n")

    # ---- raw scanner comparison ----
    aggs = [x for x in (parse_trivy(rd), parse_grype(rd)) if x]
    if aggs:
        headers = ["Tool", "Images", "Raw findings", "Unique CVEs",
                   "Fixable", "Critical", "High", "Medium"]
        print("## Raw image-scanner findings (same CRI-O tarballs)\n")
        print(md_table(headers, [a.row() for a in aggs]))
        print("\n_Trivy and Grype scan the identical exported image tarballs. "
              "Plexar ingests this same finding set, then applies context._\n")

    # ---- kubescape ----
    ks = parse_kubescape(rd)
    if ks:
        print("## Kubescape (posture / config)\n")
        print(f"- Controls evaluated: **{ks['controls_total']}**, "
              f"failed: **{ks['controls_failed']}**"
              + (f", compliance score: **{ks['score']}**" if ks.get("score") is not None else ""))
        print("\n_Kubescape is misconfiguration-focused; not directly comparable "
              "on CVE counts. Included for completeness._\n")

    # ---- plexar funnel ----
    p = parse_plexar(rd)
    if p:
        print("## Plexar reduction funnel\n")
        rows = [
            ["1. Raw findings (all severities)", p["raw"], "what a raw scanner dumps"],
            ["2. Has a fix available", p["fixable"], "you can't act on unfixable"],
            ["3. Severity ≥ High", p["critical"] + p["high"],
             f"{p['critical']} critical + {p['high']} high"],
            ["4. On internet-reachable pods (≥High)",
             p["reachable_crit"] + p["reachable_high"],
             f"{p['reachable_crit']} crit + {p['reachable_high']} high, reachable"],
        ]
        if p["has_allcves"] and p["total_entries"]:
            pct = 100.0 * p["inuse_entries"] / p["total_entries"]
            rows.append(["5. Loaded at runtime (in use)", p["inuse_entries"],
                         f"{pct:.0f}% of captured CVEs; needs /proc profiling"])
        print(md_table(["Stage", "CVEs", "Note"], rows))
        print()
        print(f"- Pods scanned: **{p['pods']}**, cluster score: "
              f"**{p['cluster_score']}**, NetworkPolicies: **{p['netpols']}**")
        if p["has_allcves"]:
            print(f"- Dedup (from full CVE list): **{len(p['unique_cve'])}** unique CVE IDs, "
                  f"**{len(p['unique_fix'])}** unique (CVE, package, fix) remediations — "
                  f"i.e. {p['raw']} instances collapse to ~{len(p['unique_fix'])} distinct fixes.")
        else:
            print("- ⚠ Dedup/in-use unavailable: this scan has no `allCVEs` "
                  "(only top-10 per pod). Re-run `plexar scan` with the current "
                  "build to capture full CVE lists, and enable `/proc` runtime "
                  "profiling for the in-use stage.")
        print()

    if not aggs and not p:
        print("_No parseable results found. Did compare.sh run and populate "
              "the results directory?_")


if __name__ == "__main__":
    main()
