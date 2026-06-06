package scorer

import (
	"fmt"

	"github.com/plexar-io/plexar/internal/types"
)

func maxCVEScore() int         { return activeWeights.CVE }
func maxBlastScore() int       { return activeWeights.Blast }
func maxPolicyGapScore() int   { return activeWeights.PolicyGap }
func maxPermScore() int        { return activeWeights.Permissions }
func maxSensitivityScore() int { return activeWeights.Sensitivity }

// Score computes the composite Plexar risk score for a pod
func Score(vuln types.VulnSummary, blast types.BlastRadius, perm types.PodPermissions) types.PlexarScore {
	cveScore := scoreCVE(vuln)
	blastScore := scoreBlast(blast)
	policyGapScore := scorePolicyGap(blast)
	permScore := scorePerm(perm)
	sensitivityScore := scoreSensitivity(blast)

	total := cveScore + blastScore + policyGapScore + permScore + sensitivityScore
	if total > 100 {
		total = 100
	}

	tier := tierFromScore(total)
	roast := generateRoast(vuln, blast, perm, total, tier)
	recs := generateRecommendations(vuln, blast, perm)

	return types.PlexarScore{
		PodName:          vuln.PodName,
		Namespace:        "",
		ImageName:        vuln.ImageName,
		Total:            total,
		Tier:             tier,
		CVEScore:         cveScore,
		BlastScore:       blastScore,
		PermScore:        permScore,
		PolicyGapScore:   policyGapScore,
		SensitivityScore: sensitivityScore,
		Vulns:            vuln,
		Blast:            blast,
		Permissions:      perm,
		Recommendations:  recs,
		Roast:            roast,
	}
}

func scoreCVE(v types.VulnSummary) int {
	score := v.Critical*8 + v.High*4 + v.Medium*1
	if score > maxCVEScore() {
		return maxCVEScore()
	}
	return score
}

func scoreBlast(b types.BlastRadius) int {
	count := len(b.ReachableTargets)
	if count == 0 {
		return 0
	}
	max := maxBlastScore()
	score := count * 3
	if b.InternetAccess {
		score += 5
	}
	if score > max {
		return max
	}
	return score
}

func scorePolicyGap(b types.BlastRadius) int {
	max := maxPolicyGapScore()
	score := 0
	if !b.HasNetworkPolicy {
		score += max * 3 / 4
	}
	if b.UnrestrictedEgress {
		score += max / 4
	}
	if score > max {
		return max
	}
	return score
}

func scorePerm(p types.PodPermissions) int {
	max := maxPermScore()
	score := 0
	if p.RunAsRoot {
		score += 5
	}
	if p.Privileged {
		score += 5
	}
	if !p.ReadOnlyRootFS {
		score += 2
	}
	if p.HostNetwork {
		score += 3
	}
	if p.AllowPrivilegeEsc {
		score += 2
	}
	if len(p.EnvSecrets) > 0 {
		score += 3
	}
	if score > max {
		return max
	}
	return score
}

func scoreSensitivity(b types.BlastRadius) int {
	max := maxSensitivityScore()
	score := len(b.DataStoreAccess) * 3
	if score > max {
		return max
	}
	return score
}

func tierFromScore(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func generateRoast(v types.VulnSummary, b types.BlastRadius, p types.PodPermissions, total int, tier string) string {
	if tier == "critical" && !b.HasNetworkPolicy {
		return fmt.Sprintf("%s has %d critical CVEs with full network access. An attacker's VIP pass to your cluster.", v.PodName, v.Critical)
	}
	if tier == "critical" {
		return fmt.Sprintf("%s is a ticking time bomb — %d critical CVEs and access to %d services.", v.PodName, v.Critical, len(b.ReachableTargets))
	}
	if tier == "high" && !b.HasNetworkPolicy {
		return fmt.Sprintf("%s has no NetworkPolicy and can reach %d services. That's a lot of blast radius.", v.PodName, len(b.ReachableTargets))
	}
	if tier == "low" {
		return fmt.Sprintf("%s is looking pretty good. Keep it up.", v.PodName)
	}
	return fmt.Sprintf("%s scores %d/100. Room for improvement.", v.PodName, total)
}

func generateRecommendations(v types.VulnSummary, b types.BlastRadius, p types.PodPermissions) []types.Recommendation {
	var recs []types.Recommendation

	if !b.HasNetworkPolicy {
		recs = append(recs, types.Recommendation{
			Priority:    "critical",
			Title:       "Add a NetworkPolicy",
			Description: fmt.Sprintf("Restrict %s to only its configured dependencies. Currently can reach %d services + internet.", v.PodName, len(b.ReachableTargets)),
			Command:     fmt.Sprintf("plexar generate netpol %s --namespace %s", v.PodName, v.PodName),
		})
	}

	if v.Critical > 0 && v.FixableCount > 0 {
		recs = append(recs, types.Recommendation{
			Priority:    "high",
			Title:       "Update base image",
			Description: fmt.Sprintf("%d fixable CVEs including %d critical. Update image to patch known vulnerabilities.", v.FixableCount, v.Critical),
		})
	}

	if p.RunAsRoot {
		recs = append(recs, types.Recommendation{
			Priority:    "high",
			Title:       "Run as non-root",
			Description: "Container runs as uid 0. Set runAsNonRoot: true and runAsUser: 1000 in securityContext.",
		})
	}

	if p.Privileged {
		recs = append(recs, types.Recommendation{
			Priority:    "critical",
			Title:       "Remove privileged mode",
			Description: "Container runs in privileged mode — full host access. Remove unless absolutely required.",
		})
	}

	return recs
}
