package conversion

import (
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// extractTactics flattens all tactics from a slice of Mitre entries into a
// single string slice.
func extractTactics(mitre []model.Mitre) []string {
	tactics := []string{}
	for _, m := range mitre {
		tactics = append(tactics, m.Tactics...)
	}
	return tactics
}

// extractTechniques returns the parent technique IDs (T1059) of all Mitre
// entries, deduplicated in first-seen order. A sub-technique ID (T1059.001)
// contributes its parent.
func extractTechniques(mitre []model.Mitre) []string {
	techniques := []string{}
	seen := map[string]bool{}
	for _, m := range mitre {
		for _, t := range m.Techniques {
			parent, _, _ := strings.Cut(t, ".")
			if !seen[parent] {
				seen[parent] = true
				techniques = append(techniques, parent)
			}
		}
	}
	return techniques
}

// extractSubTechniques returns the full sub-technique IDs (T1059.001) of all
// Mitre entries, deduplicated in first-seen order.
func extractSubTechniques(mitre []model.Mitre) []string {
	subs := []string{}
	seen := map[string]bool{}
	for _, m := range mitre {
		for _, t := range m.Techniques {
			if strings.Contains(t, ".") && !seen[t] {
				seen[t] = true
				subs = append(subs, t)
			}
		}
	}
	return subs
}

// mergeTechniques is the reverse of extractTechniques/extractSubTechniques: it
// combines the parent and sub-technique lists of an ARM rule into one prodyaml
// technique list. A parent that is implied by a listed sub-technique is
// dropped, so the list round-trips to the same ARM output.
func mergeTechniques(techniques, subTechniques []string) []string {
	all := append(append([]string{}, techniques...), subTechniques...)

	parents := map[string]bool{}
	for _, t := range all {
		if parent, _, ok := strings.Cut(t, "."); ok {
			parents[parent] = true
		}
	}

	merged := []string{}
	seen := map[string]bool{}
	for _, t := range all {
		if seen[t] || parents[t] {
			continue
		}
		seen[t] = true
		merged = append(merged, t)
	}
	return merged
}
