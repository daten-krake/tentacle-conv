package conversion

import "github.com/tentacle-conv/internal/model"

// extractTactics flattens all tactics from a slice of Mitre entries into a
// single string slice.
func extractTactics(mitre []model.Mitre) []string {
	tactics := []string{}
	for _, m := range mitre {
		tactics = append(tactics, m.Tactics...)
	}
	return tactics
}

// extractTechniques flattens all techniques from a slice of Mitre entries into a
// single string slice.
func extractTechniques(mitre []model.Mitre) []string {
	techniques := []string{}
	for _, m := range mitre {
		techniques = append(techniques, m.Techniques...)
	}
	return techniques
}