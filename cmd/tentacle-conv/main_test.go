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

func writeRuleWithEntity(t *testing.T, dir, name, entityType, identifier string) string {
	t.Helper()
	body := "name: " + name + "\nseverity: Low\nquery: print 1\nquery_frequency: PT1H\nquery_period: PT1H\n" +
		"entity_mapping:\n  - entity_type: " + entityType + "\n    field_mapping:\n      - identifier: " + identifier + "\n        column_name: C\n"
	p := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckEntitiesFlag(t *testing.T) {
	dir := t.TempDir()
	clean := writeRuleWithEntity(t, dir, "Clean", "Host", "AzureID")
	weak := writeRuleWithEntity(t, dir, "Weak", "Account", "Name")
	bad := writeRuleWithEntity(t, dir, "Bad", "Acount", "Name")
	outdir := filepath.Join(dir, "must-not-exist")

	t.Run("no outpath and no files written", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, "yaml-to-arm", "-check-entities", "-file", clean)
		if code != 0 {
			t.Fatalf("exit %d: %s %s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "ok") || !strings.Contains(stdout, "1 file(s) checked") {
			t.Errorf("stdout = %q", stdout)
		}
	})

	t.Run("warnings keep exit 0, strict fails", func(t *testing.T) {
		if code, stdout, _ := runCLI(t, "yaml-to-arm", "-check-entities", "-file", weak); code != 0 || !strings.Contains(stdout, "warning") {
			t.Errorf("exit %d, stdout %q", code, stdout)
		}
		if code, _, _ := runCLI(t, "yaml-to-arm", "-check-entities", "-strict", "-file", weak); code != 1 {
			t.Errorf("-strict exit %d, want 1", code)
		}
	})

	t.Run("errors fail", func(t *testing.T) {
		code, stdout, _ := runCLI(t, "yaml-to-bicep", "-check-entities", "-file", bad)
		if code != 1 || !strings.Contains(stdout, "unknown entity_type") {
			t.Errorf("exit %d, stdout %q", code, stdout)
		}
	})

	t.Run("several files, flags after the first file", func(t *testing.T) {
		code, stdout, _ := runCLI(t, "yaml-to-json", "-file", clean, weak, bad, "-check-entities")
		if code != 1 || !strings.Contains(stdout, "3 file(s) checked") {
			t.Errorf("exit %d, stdout %q", code, stdout)
		}
	})

	t.Run("target follows the command", func(t *testing.T) {
		_, sentinel, _ := runCLI(t, "yaml-to-arm", "-check-entities", "-file", clean)
		_, xdr, _ := runCLI(t, "yaml-to-xdr", "-check-entities", "-file", clean)
		if strings.Contains(sentinel, "ReportId") || !strings.Contains(xdr, "ReportId") {
			t.Errorf("sentinel %q\nxdr %q", sentinel, xdr)
		}
	})

	t.Run("strict alone is rejected", func(t *testing.T) {
		if code, _, stderr := runCLI(t, "yaml-to-arm", "-strict", "-file", clean, "-outpath", outdir); code != 2 || !strings.Contains(stderr, "-check-entities") {
			t.Errorf("exit %d, stderr %q", code, stderr)
		}
	})

	t.Run("not available on arm-to-yaml", func(t *testing.T) {
		if code, _, _ := runCLI(t, "arm-to-yaml", "-check-entities", "-file", clean); code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
	})

	if _, err := os.Stat(outdir); err == nil {
		t.Error("an output directory was created")
	}
}

func TestConversionRejectsInvalidEntityMapping(t *testing.T) {
	dir := t.TempDir()
	bad := writeRuleWithEntity(t, dir, "Bad", "Host", "HostNme")
	code, _, stderr := runCLI(t, "yaml-to-arm", "-file", bad, "-outpath", filepath.Join(dir, "out"))
	if code != 1 || !strings.Contains(stderr, `identifier "HostNme" is not valid for Host`) {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}
