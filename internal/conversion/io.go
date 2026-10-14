package conversion

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// maxFileNameLen bounds the rule-name part of an output file name so the full
// name stays within common filesystem limits (255 bytes).
const maxFileNameLen = 200

// loadAnalytic reads a prodyaml file, rejects unknown fields (so typos such as
// `query_freqency` are not silently ignored) and validates required fields and
// the hard limits of the entity mapping.
func loadAnalytic(file string) (model.Analytic, error) {
	a, err := decodeAnalytic(file)
	if err != nil {
		return a, fmt.Errorf("%s: %w", file, err)
	}
	if err := a.Validate(); err != nil {
		return a, fmt.Errorf("invalid rule in %s: %w", file, err)
	}
	log.Println("read in: " + file)
	return a, nil
}

// safeFileName turns a rule name into a single, safe path element. Path
// separators, characters reserved on common filesystems and control
// characters become '_'; leading/trailing dots and spaces are trimmed so the
// result can never be hidden, empty, or escape the output directory.
func safeFileName(name string) (string, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return '_'
		case strings.ContainsRune(`/\:*?"<>|`, r):
			return '_'
		}
		return r
	}, name)
	cleaned = strings.Trim(cleaned, ". ")
	if len(cleaned) > maxFileNameLen {
		cleaned = strings.Trim(strings.ToValidUTF8(cleaned[:maxFileNameLen], ""), ". ")
	}

	if cleaned == "" {
		return "", fmt.Errorf("rule name %q cannot be used as a file name", name)
	}
	return cleaned, nil
}

// outputPath returns outpath/<safe rule name>.<ext>.
func outputPath(outpath, name, ext string) (string, error) {
	base, err := safeFileName(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(outpath, base+"."+ext), nil
}

// writeOutput writes data to outpath/<safe rule name>.<ext>, creating outpath
// if needed.
func writeOutput(outpath, name, ext string, data []byte) error {
	outFile, err := outputPath(outpath, name, ext)
	if err != nil {
		return err
	}
	return writeFile(outpath, outFile, data)
}

func writeFile(outpath, outFile string, data []byte) error {
	if err := os.MkdirAll(outpath, 0o755); err != nil {
		return fmt.Errorf("creating output directory %s: %w", outpath, err)
	}
	if err := os.WriteFile(outFile, data, 0o644); err != nil {
		return fmt.Errorf("writing file %s: %w", outFile, err)
	}
	return nil
}
