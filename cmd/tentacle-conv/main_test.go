package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testRule = `name: CLI_Test_Rule
severity: Low
query: print 1
query_frequency: PT1H
query_period: PT1H
`

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func writeRule(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rule.yaml")
	if err := os.WriteFile(p, []byte(testRule), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSubcommands(t *testing.T) {
	for cmd, ext := range map[string]string{
		"yaml-to-arm":   "json",
		"yaml-to-json":  "json",
		"yaml-to-bicep": "bicep",
	} {
		t.Run(cmd, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "new", "dir")
			code, _, stderr := runCLI(t, cmd, "-file", writeRule(t), "-outpath", out)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			if _, err := os.Stat(filepath.Join(out, "CLI_Test_Rule."+ext)); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestLegacyModeStillWorksButWarns(t *testing.T) {
	out := t.TempDir()
	code, _, stderr := runCLI(t, "-mode", "arm", "-file", writeRule(t), "-outpath", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "deprecated") || !strings.Contains(stderr, "yaml-to-arm") {
		t.Errorf("expected a deprecation warning naming the replacement, got %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(out, "CLI_Test_Rule.json")); err != nil {
		t.Error(err)
	}
}

func TestErrors(t *testing.T) {
	rule := writeRule(t)
	out := t.TempDir()
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no arguments", nil, 2, "Usage"},
		{"unknown command", []string{"frobnicate"}, 2, "unknown command"},
		{"missing file", []string{"yaml-to-arm", "-outpath", out}, 1, "-file"},
		{"missing outpath", []string{"yaml-to-arm", "-file", rule}, 1, "-outpath"},
		{"-array on a yaml command", []string{"yaml-to-arm", "-file", rule, "-outpath", out, "-array"}, 2, "not defined"},
		{"legacy -array outside yaml", []string{"-mode", "arm", "-array", "-file", rule, "-outpath", out}, 1, "-array"},
		{"legacy unknown mode", []string{"-mode", "xml", "-file", rule, "-outpath", out}, 1, "unknown mode"},
		{"extra argument", []string{"yaml-to-arm", "-file", rule, "-outpath", out, "stray"}, 2, "unexpected argument"},
		{"conversion error", []string{"yaml-to-arm", "-file", filepath.Join(out, "nope.yaml"), "-outpath", out}, 1, "reading file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d (stderr %q)", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr, tt.wantErr)
			}
		})
	}
}

func TestVersionAndHelp(t *testing.T) {
	for _, arg := range []string{"version", "-version"} {
		code, stdout, _ := runCLI(t, arg)
		if code != 0 || !strings.Contains(stdout, version) {
			t.Errorf("%s: exit %d, stdout %q", arg, code, stdout)
		}
	}
	code, stdout, _ := runCLI(t, "help")
	if code != 0 || !strings.Contains(stdout, "yaml-to-bicep") {
		t.Errorf("help: exit %d, stdout %q", code, stdout)
	}
}
