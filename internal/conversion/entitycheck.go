package conversion

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

// EntityTarget selects which service's rules the entity mappings are checked
// against.
type EntityTarget int

const (
	// TargetSentinel is used for the ARM, REST API, Bicep and OpenTofu outputs.
	TargetSentinel EntityTarget = iota
	// TargetXDR is used for the Defender XDR output.
	TargetXDR
)

// Finding levels.
const (
	LevelError   = "error"
	LevelWarning = "warning"
)

// EntityFinding is one problem found in a rule's entity mapping.
type EntityFinding struct {
	Level   string
	Entity  int // index into entity_mapping, -1 when it concerns the rule as a whole
	Message string
}

// CheckEntities runs every entity mapping check for the target. Errors are the
// hard limits every conversion enforces; warnings are advice that only the
// check mode reports.
func CheckEntities(a model.Analytic, target EntityTarget) []EntityFinding {
	var out []EntityFinding

	for _, issue := range a.EntityMappingIssues() {
		out = append(out, EntityFinding{LevelError, issue.Index, issue.Message})
	}

	for i, em := range a.EntityMapping {
		spec, known := model.SentinelEntities[em.EntityType]
		if !known {
			continue
		}
		ids := make([]string, 0, len(em.FieldMapping))
		for _, fm := range em.FieldMapping {
			ids = append(ids, fm.Identifier)
		}

		allLegacy := len(ids) > 0
		for _, id := range ids {
			if !spec.IsLegacy(id) {
				allLegacy = false
			}
			if spec.IsLegacy(id) {
				out = append(out, EntityFinding{LevelWarning, i, fmt.Sprintf(
					"identifier %s is kept for backward compatibility only and is not part of the %s schema; prefer a documented identifier", id, em.EntityType)})
			}
		}

		switch {
		case spec.NeedsInternal:
			out = append(out, EntityFinding{LevelWarning, i, fmt.Sprintf(
				"%s cannot be identified strongly from mappable identifiers alone (it needs an internal entity such as a host); the entity may correlate poorly",
				em.EntityType)})
		case allLegacy:
			// Only legacy identifiers: the warning above already covers it.
		case !spec.IsStrong(ids):
			msg := fmt.Sprintf("only weak identifiers (%s) are mapped for %s; add one of: %s",
				strings.Join(ids, ", "), em.EntityType, describeStrong(spec))
			if em.EntityType == "Account" && contains(ids, "Name") {
				msg += ". An Account Name alone is weak, and built-in names such as ADMINISTRATOR, SYSTEM or ROOT are dropped from the alert"
			}
			out = append(out, EntityFinding{LevelWarning, i, msg})
		}
	}

	out = append(out, columnFindings(a)...)

	if target == TargetXDR {
		_, warnings := buildXDREntityMappings(a.EntityMapping)
		for _, w := range warnings {
			out = append(out, EntityFinding{LevelWarning, -1, w})
		}
		if !reportIDCol.MatchString(a.Query) {
			out = append(out, EntityFinding{LevelWarning, -1,
				"query does not mention ReportId; Defender recommends projecting Timestamp and ReportId (plus DeviceId for MDE tables)"})
		}
	}
	return out
}

func describeStrong(spec model.EntitySpec) string {
	if len(spec.Strong) == 0 {
		return "(no strong combination is possible)"
	}
	parts := make([]string, len(spec.Strong))
	for i, combo := range spec.Strong {
		parts[i] = strings.Join(combo, "+")
	}
	return strings.Join(parts, ", ")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// columnFindings warns about mapped columns that the query visibly does not
// return. It only judges queries whose last operator it can read.
func columnFindings(a model.Analytic) []EntityFinding {
	cols, complete := queryOutputColumns(a.Query)
	if !complete {
		return nil
	}
	var out []EntityFinding
	for i, em := range a.EntityMapping {
		for _, fm := range em.FieldMapping {
			if fm.ColumnName == "" || cols[strings.ToLower(fm.ColumnName)] {
				continue
			}
			out = append(out, EntityFinding{LevelWarning, i, fmt.Sprintf(
				"column %q (identifier %s) is not in the query output", fm.ColumnName, fm.Identifier)})
		}
	}
	return out
}

// ── KQL output column scan ──────────────────────────────────────────────────

var (
	identRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	namedItemRe  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=[^=~]`)
	opKeywordRe  = regexp.MustCompile(`(?i)^(project|summarize|extend)\b`)
	bareCountRe  = regexp.MustCompile(`(?i)^count\s*\(\s*\)$`)
	projectOpRe  = regexp.MustCompile(`(?i)^project\s+(.*)$`)
	extendOpRe   = regexp.MustCompile(`(?i)^extend\s+(.*)$`)
	summarizeRe  = regexp.MustCompile(`(?i)^summarize\s+(.*)$`)
	whitespaceRe = regexp.MustCompile(`\s+`)
)

// queryOutputColumns determines the columns returned by the last statement of
// a KQL query. The names are lower-cased. complete is true only when the set
// is exact: the last operator is a project, or a summarize whose columns are
// all named. With a trailing extend the known names are returned with
// complete=false, since earlier columns are also present.
func queryOutputColumns(query string) (cols map[string]bool, complete bool) {
	stmts := splitTopLevel(stripKQLComments(query), ';')
	var last string
	for i := len(stmts) - 1; i >= 0; i-- {
		if strings.TrimSpace(stmts[i]) != "" {
			last = stmts[i]
			break
		}
	}
	if last == "" {
		return nil, false
	}

	pipes := splitTopLevel(last, '|')
	op := whitespaceRe.ReplaceAllString(strings.TrimSpace(pipes[len(pipes)-1]), " ")
	if len(pipes) < 2 || !opKeywordRe.MatchString(op) {
		return nil, false
	}

	cols = map[string]bool{}
	switch {
	case projectOpRe.MatchString(op):
		items := splitTopLevel(projectOpRe.FindStringSubmatch(op)[1], ',')
		for _, it := range items {
			name, ok := itemName(it)
			if !ok {
				return nil, false
			}
			cols[strings.ToLower(name)] = true
		}
		return cols, true

	case extendOpRe.MatchString(op):
		for _, it := range splitTopLevel(extendOpRe.FindStringSubmatch(op)[1], ',') {
			if m := namedItemRe.FindStringSubmatch(strings.TrimSpace(it)); m != nil {
				cols[strings.ToLower(m[1])] = true
			}
		}
		return cols, false

	case summarizeRe.MatchString(op):
		body := summarizeRe.FindStringSubmatch(op)[1]
		aggs, by := body, ""
		if loc := topLevelBy(body); loc >= 0 {
			aggs, by = body[:loc], body[loc:]
			by = strings.TrimSpace(by[len("by"):])
		}
		for _, it := range splitTopLevel(aggs, ',') {
			it = strings.TrimSpace(it)
			if it == "" {
				continue
			}
			if bareCountRe.MatchString(it) {
				cols["count_"] = true
				continue
			}
			m := namedItemRe.FindStringSubmatch(it)
			if m == nil {
				return nil, false
			}
			cols[strings.ToLower(m[1])] = true
		}
		for _, it := range splitTopLevel(by, ',') {
			if strings.TrimSpace(it) == "" {
				continue
			}
			name, ok := itemName(it)
			if !ok {
				return nil, false
			}
			cols[strings.ToLower(name)] = true
		}
		return cols, true
	}
	return nil, false
}

// itemName returns the output column name of a project/by item: "name = expr"
// or a bare identifier.
func itemName(item string) (string, bool) {
	item = strings.TrimSpace(item)
	if m := namedItemRe.FindStringSubmatch(item); m != nil {
		return m[1], true
	}
	if identRe.MatchString(item) {
		return item, true
	}
	return "", false
}

// topLevelBy returns the offset of the `by` keyword outside brackets/strings,
// or -1.
func topLevelBy(s string) int {
	depth := 0
	var quote rune
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == '\\' {
				i++
			} else if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '(' || r == '[' || r == '{':
			depth++
		case r == ')' || r == ']' || r == '}':
			depth--
		case depth == 0 && (r == 'b' || r == 'B') && i+1 < len(rs) && (rs[i+1] == 'y' || rs[i+1] == 'Y'):
			before := i == 0 || rs[i-1] == ' ' || rs[i-1] == '\t'
			after := i+2 >= len(rs) || rs[i+2] == ' ' || rs[i+2] == '\t'
			if before && after {
				return len(string(rs[:i]))
			}
		}
	}
	return -1
}

// splitTopLevel splits s at sep outside quotes and brackets.
func splitTopLevel(s string, sep rune) []string {
	var parts []string
	var cur strings.Builder
	depth := 0
	var quote rune
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			cur.WriteRune(r)
			if r == '\\' && i+1 < len(rs) {
				i++
				cur.WriteRune(rs[i])
			} else if r == quote {
				quote = 0
			}
			continue
		case r == '"' || r == '\'':
			quote = r
		case r == '(' || r == '[' || r == '{':
			depth++
		case r == ')' || r == ']' || r == '}':
			depth--
		case r == sep && depth == 0:
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	return append(parts, cur.String())
}

// stripKQLComments removes // comments that are outside string literals.
func stripKQLComments(s string) string {
	var b strings.Builder
	var quote rune
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			b.WriteRune(r)
			if r == '\\' && i+1 < len(rs) {
				i++
				b.WriteRune(rs[i])
			} else if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			b.WriteRune(r)
		case r == '/' && i+1 < len(rs) && rs[i+1] == '/':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			b.WriteRune('\n')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── reporting ───────────────────────────────────────────────────────────────

// CheckEntityFiles checks the entity mappings of each file, writes the findings
// to out and returns the process exit code: 1 if any file has an error (or any
// finding when strict is set, or cannot be read), otherwise 0. No output files
// are written.
func CheckEntityFiles(files []string, target EntityTarget, strict bool, out io.Writer) int {
	var errCount, warnCount, bad int

	for _, file := range files {
		a, err := decodeAnalytic(file)
		if err != nil {
			fmt.Fprintf(out, "%s: error: %v\n", file, err)
			errCount++
			bad++
			continue
		}

		findings := CheckEntities(a, target)
		label := a.Name
		if label == "" {
			label = "(unnamed)"
		}
		fileBad := false
		for _, f := range findings {
			where := ""
			if f.Entity >= 0 && f.Entity < len(a.EntityMapping) {
				where = fmt.Sprintf("entity_mapping[%d] (%s): ", f.Entity, a.EntityMapping[f.Entity].EntityType)
			}
			fmt.Fprintf(out, "%s: rule %q: %s: %s%s\n", file, label, f.Level, where, f.Message)
			switch f.Level {
			case LevelError:
				errCount++
				fileBad = true
			default:
				warnCount++
				if strict {
					fileBad = true
				}
			}
		}
		if fileBad {
			bad++
		} else if len(findings) == 0 {
			fmt.Fprintf(out, "%s: rule %q: ok\n", file, label)
		}
	}

	fmt.Fprintf(out, "\n%d file(s) checked: %d error(s), %d warning(s)", len(files), errCount, warnCount)
	if strict && warnCount > 0 {
		fmt.Fprint(out, " (-strict: warnings count as failures)")
	}
	fmt.Fprintln(out)

	if bad > 0 {
		return 1
	}
	return 0
}

// decodeAnalytic reads a prodyaml file with strict decoding but without
// validating it, so the checks can report every problem themselves.
func decodeAnalytic(file string) (model.Analytic, error) {
	var a model.Analytic
	f, err := os.ReadFile(file)
	if err != nil {
		return a, fmt.Errorf("reading file: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(f))
	dec.KnownFields(true)
	if err := dec.Decode(&a); err != nil {
		if errors.Is(err, io.EOF) {
			return a, errors.New("file is empty")
		}
		return a, fmt.Errorf("unmarshaling YAML: %w", err)
	}
	return a, nil
}
