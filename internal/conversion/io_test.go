package conversion

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSafeFileName(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"Files_with_double_extensions", "Files_with_double_extensions", false},
		{"Login/Logout", "Login_Logout", false},
		{`a\b`, "a_b", false},
		{"../../etc/passwd", "_.._etc_passwd", false},
		{"..", "", true},
		{".hidden", "hidden", false},
		{"", "", true},
		{"   ", "", true},
		{"CON: bad?*name", "CON_ bad__name", false},
		{"tab\tand\nnewline", "tab_and_newline", false},
		{"Üñïcödé rule", "Üñïcödé rule", false},
	}
	for _, tt := range tests {
		got, err := safeFileName(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("safeFileName(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("safeFileName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSafeFileName_Length(t *testing.T) {
	got, err := safeFileName(strings.Repeat("é", 300))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxFileNameLen || !utf8.ValidString(got) {
		t.Errorf("name not truncated safely: %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
}
