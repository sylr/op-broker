package client

import (
	"slices"
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	src := `
# comment
PLAIN=value
SPACED =  padded value   # trailing comment
export EXPORTED=yes
SINGLE='it is # not a comment'
DOUBLE="line1\nline2 \"quoted\" \$HOME \\"
MULTI="first
second"
REF=op://Dev/db/password
EMPTY=
HASH=a#b
`
	vars, err := ParseDotenv(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvVar{
		{"PLAIN", "value"},
		{"SPACED", "padded value"},
		{"EXPORTED", "yes"},
		{"SINGLE", "it is # not a comment"},
		{"DOUBLE", "line1\nline2 \"quoted\" $HOME \\"},
		{"MULTI", "first\nsecond"},
		{"REF", "op://Dev/db/password"},
		{"EMPTY", ""},
		{"HASH", "a#b"},
	}
	if !slices.Equal(vars, want) {
		t.Fatalf("ParseDotenv =\n%q\nwant\n%q", vars, want)
	}
}

func TestParseDotenvErrors(t *testing.T) {
	for name, src := range map[string]string{
		"no equals":          "JUSTAKEY\n",
		"bad key":            "1KEY=x\n",
		"unterminated '":     "K='abc\n",
		"unterminated \"":    "K=\"abc\n",
		"trailer after '":    "K='a' b\n",
		"trailer after \"":   "K=\"a\" b\n",
		"unsupported escape": `K="\x"` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDotenv(strings.NewReader(src)); err == nil {
				t.Fatalf("ParseDotenv(%q) succeeded", src)
			}
		})
	}
}

func TestMergeEnvPrecedence(t *testing.T) {
	file1 := []EnvVar{{"A", "file1"}, {"B", "file1"}, {"C", "file1"}}
	file2 := []EnvVar{{"B", "file2"}, {"D", "file2"}}
	environ := []string{"C=process", "E=process"}
	got := MergeEnv(environ, file1, file2)
	want := []string{"A=file1", "B=file2", "C=process", "D=file2", "E=process"}
	if !slices.Equal(got, want) {
		t.Fatalf("MergeEnv = %v, want %v", got, want)
	}
}

func TestEnvRefsAndSubstitute(t *testing.T) {
	env := []string{
		"DB=op://Dev/db/password",
		"DB2=op://Dev/db/password",
		"URL=postgres://u:op://Dev/db/password@h", // embedded refs are not resolved
		"OTHER=x",
	}
	refs := EnvRefs(env)
	if !slices.Equal(refs, []string{"op://Dev/db/password"}) {
		t.Fatalf("EnvRefs = %v", refs)
	}
	got, err := SubstituteEnv(env, map[string]string{"op://Dev/db/password": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DB=s3cret", "DB2=s3cret", "URL=postgres://u:op://Dev/db/password@h", "OTHER=x"}
	if !slices.Equal(got, want) {
		t.Fatalf("SubstituteEnv = %v, want %v", got, want)
	}
}
