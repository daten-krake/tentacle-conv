package conversion

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// decodeBicepString interprets a single-quoted Bicep string literal the way the
// Bicep compiler does and returns its value. It rejects anything the compiler
// would not accept as one literal: an unescaped quote, a raw newline, an
// unescaped "${" (interpolation) or an unknown escape.
func decodeBicepString(lit string) (string, error) {
	if len(lit) < 2 || lit[0] != '\'' || lit[len(lit)-1] != '\'' {
		return "", fmt.Errorf("not a single-quoted literal: %q", lit)
	}
	body := lit[1 : len(lit)-1]

	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\'':
			return "", fmt.Errorf("unescaped quote at %d in %q", i, lit)
		case c == '\n' || c == '\r':
			return "", fmt.Errorf("raw line break at %d in %q", i, lit)
		case c == '$' && i+1 < len(body) && body[i+1] == '{':
			return "", fmt.Errorf("unescaped interpolation at %d in %q", i, lit)
		case c != '\\':
			b.WriteByte(c)
			continue
		}

		i++
		if i >= len(body) {
			return "", fmt.Errorf("dangling backslash in %q", lit)
		}
		switch body[i] {
		case '\\', '\'', '$':
			b.WriteByte(body[i])
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			return "", fmt.Errorf("unknown escape \\%c in %q", body[i], lit)
		}
	}
	return b.String(), nil
}

// decodeBicepQuery decodes the output of bicepQuery, which is either a
// single-quoted literal or a verbatim ”' multi-line string.
func decodeBicepQuery(lit string) (string, error) {
	if !strings.HasPrefix(lit, "'''") {
		return decodeBicepString(lit)
	}
	if !strings.HasPrefix(lit, "'''\n") || !strings.HasSuffix(lit, "'''") || len(lit) < 7 {
		return "", fmt.Errorf("malformed multi-line string: %q", lit)
	}
	body := lit[4 : len(lit)-3]
	if strings.Contains(body, "'''") {
		return "", fmt.Errorf("''' inside multi-line string: %q", lit)
	}
	if strings.HasSuffix(body, "'") {
		return "", fmt.Errorf("multi-line string body ends with a quote: %q", lit)
	}
	return body, nil
}

var escapeSeeds = []string{
	"", "plain", "it's", `C:\Windows\temp`, "${workspace}", "$", "${", `\${`, `\'`,
	"line1\nline2", "line1\r\nline2", "tab\there", "'''", "a'''b", "ends with quote'",
	"multi\nline\n'''\nquote", "x\n'", "''", "\n", "\\", "é\u2028\u0000",
}

func FuzzBicepEscape(f *testing.F) {
	for _, s := range escapeSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := decodeBicepString("'" + bicepEscape(s) + "'")
		if err != nil {
			t.Fatal(err)
		}
		if got != s {
			t.Errorf("round trip changed value: %q -> %q", s, got)
		}
	})
}

func FuzzBicepQuery(f *testing.F) {
	for _, s := range escapeSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := decodeBicepQuery(bicepQuery(s))
		if err != nil {
			t.Fatal(err)
		}
		if got != s {
			t.Errorf("round trip changed value: %q -> %q", s, got)
		}
	})
}

func FuzzSafeFileName(f *testing.F) {
	for _, s := range []string{
		"", ".", "..", "../x", "a/b", `a\b`, "/abs", "name.", " name ", ".hidden",
		"CON:", "a\x00b", "é", strings.Repeat("x", 300), "../../etc/passwd",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		name, err := safeFileName(s)
		if err != nil {
			return
		}
		if name == "" || name == "." || name == ".." {
			t.Fatalf("unusable name %q for input %q", name, s)
		}
		if strings.HasPrefix(name, ".") || strings.ContainsAny(name, `/\`) {
			t.Errorf("unsafe name %q for input %q", name, s)
		}
		if len(name) > maxFileNameLen {
			t.Errorf("name too long (%d) for input %q", len(name), s)
		}
		if utf8.ValidString(s) && !utf8.ValidString(name) {
			t.Errorf("invalid UTF-8 produced from valid input %q", s)
		}
		out := filepath.Join("out", name+".yaml")
		if filepath.Dir(out) != "out" {
			t.Errorf("path %q escapes the output directory", out)
		}
	})
}
