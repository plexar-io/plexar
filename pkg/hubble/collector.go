package hubble

import (
	"sort"
	"time"

	"github.com/plexar-io/plexar/internal/types"
)

// Aggregate deduplicates and aggregates raw flows into FlowSummary per pod pair.
// It merges flows with the same source/destination pod into a single summary
// with total bytes, request counts, and unique ports/protocols.
func Aggregate(flows []types.ObservedFlow) []types.FlowSummary {
	type pairKey struct {
		src string
		dst string
	}

	summaries := make(map[pairKey]*types.FlowSummary)

	for _, f := range flows {
		if f.SrcPod == "" && f.DstPod == "" {
			continue
		}
		// Only count FORWARDED flows (not DROPPED)
		if f.Verdict != "" && f.Verdict != "FORWARDED" {
			continue
		}

		key := pairKey{src: f.SrcPod, dst: f.DstPod}
		s, ok := summaries[key]
		if !ok {
			s = &types.FlowSummary{
				SrcPod: f.SrcPod,
				DstPod: f.DstPod,
			}
			summaries[key] = s
		}

		s.TotalBytes += f.ByteCount
		s.TotalReqs += f.RequestCount

		// Track unique ports
		if !containsUint32(s.Ports, f.Port) && f.Port > 0 {
			s.Ports = append(s.Ports, f.Port)
		}

		// Track L7 protocols
		if f.L7Protocol != "" && !containsString(s.L7Protocols, f.L7Protocol) {
			s.L7Protocols = append(s.L7Protocols, f.L7Protocol)
		}

		// Keep latest timestamp
		if f.LastSeen.After(s.LastSeen) {
			s.LastSeen = f.LastSeen
		}
	}

	// Convert to slice and sort by request count descending
	result := make([]types.FlowSummary, 0, len(summaries))
	for _, s := range summaries {
		result = append(result, *s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalReqs > result[j].TotalReqs
	})

	return result
}

// FlowsToReachableTargets extracts the unique destination pod names from flows
// originating from the given source pod. This is used to build the
// ReachableTargets list in BlastRadius from observed traffic.
func FlowsToReachableTargets(flows []types.ObservedFlow, srcPod string) []string {
	seen := make(map[string]bool)
	var targets []string

	for _, f := range flows {
		if f.SrcPod != srcPod {
			continue
		}
		if f.Verdict != "" && f.Verdict != "FORWARDED" {
			continue
		}
		if f.DstPod != "" && f.DstPod != srcPod && !seen[f.DstPod] {
			seen[f.DstPod] = true
			targets = append(targets, f.DstPod)
		}
	}

	sort.Strings(targets)
	return targets
}

// HasExternalTraffic checks if any flow from the given pod goes to an external IP
// (i.e., a flow where DstPod is empty but DstIP is set)
func HasExternalTraffic(flows []types.ObservedFlow, srcPod string) bool {
	for _, f := range flows {
		if f.SrcPod == srcPod && f.DstPod == "" && f.DstIP != "" {
			if f.Verdict == "" || f.Verdict == "FORWARDED" {
				return true
			}
		}
	}
	return false
}

// FilterByAge removes flows older than the given duration
func FilterByAge(flows []types.ObservedFlow, maxAge time.Duration) []types.ObservedFlow {
	cutoff := time.Now().Add(-maxAge)
	var result []types.ObservedFlow
	for _, f := range flows {
		if f.LastSeen.After(cutoff) || f.LastSeen.IsZero() {
			result = append(result, f)
		}
	}
	return result
}

func containsUint32(slice []uint32, val uint32) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsString(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
