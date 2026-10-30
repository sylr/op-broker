package client

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// EnvVar is a variable read from an env file.
type EnvVar struct {
	Key   string
	Value string
}

// ParseDotenv parses an env file. The supported subset is:
//
//	# comment
//	KEY=value            (unquoted; trailing " # comment" stripped, value trimmed)
//	export KEY=value
//	KEY='literal value'  (no escapes, single line)
//	KEY="value"          (escapes \n \t \" \\ \$; may span several lines)
//
// Variable interpolation is not supported.
func ParseDotenv(r io.Reader) ([]EnvVar, error) {
	var vars []EnvVar
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	lineNo := 0
	next := func() (string, bool) {
		if !sc.Scan() {
			return "", false
		}
		lineNo++
		return sc.Text(), true
	}
	for {
		line, ok := next()
		if !ok {
			break
		}
		start := lineNo
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, rest, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !validName(key) {
			return nil, fmt.Errorf("line %d: expected KEY=value", start)
		}
		rest = strings.TrimLeft(rest, " \t")

		var value string
		switch {
		case strings.HasPrefix(rest, "'"):
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated single-quoted value", start)
			}
			value = rest[1 : 1+end]
			if err := checkTrailer(rest[2+end:]); err != nil {
				return nil, fmt.Errorf("line %d: %w", start, err)
			}
		case strings.HasPrefix(rest, `"`):
			var b strings.Builder
			s := rest[1:]
			for {
				end, err := scanDoubleQuoted(s, &b)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", start, err)
				}
				if end >= 0 {
					if err := checkTrailer(s[end+1:]); err != nil {
						return nil, fmt.Errorf("line %d: %w", start, err)
					}
					break
				}
				more, ok := next()
				if !ok {
					return nil, fmt.Errorf("line %d: unterminated double-quoted value", start)
				}
				b.WriteByte('\n')
				s = more
			}
			value = b.String()
		default:
			if i := strings.Index(rest, " #"); i >= 0 {
				rest = rest[:i]
			}
			value = strings.TrimSpace(rest)
		}
		vars = append(vars, EnvVar{Key: key, Value: value})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return vars, nil
}

// scanDoubleQuoted appends the content of s up to the closing quote to b and
// returns the index of that quote, or -1 if s ends first.
func scanDoubleQuoted(s string, b *strings.Builder) (int, error) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return i, nil
		case '\\':
			if i+1 >= len(s) {
				return 0, fmt.Errorf("dangling backslash")
			}
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '"', '\\', '$':
				b.WriteByte(s[i])
			default:
				return 0, fmt.Errorf("unsupported escape \\%c", s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return -1, nil
}

func checkTrailer(s string) error {
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasPrefix(s, "#") {
		return fmt.Errorf("unexpected text after quoted value")
	}
	return nil
}

// MergeEnv merges the process environment and env files with the precedence
// of `op run`: env files override the process environment, and later files
// override earlier ones.
func MergeEnv(environ []string, files ...[]EnvVar) []string {
	values := make(map[string]string)
	var order []string
	set := func(k, v string) {
		if _, ok := values[k]; !ok {
			order = append(order, k)
		}
		values[k] = v
	}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			set(k, v)
		}
	}
	for _, vars := range files {
		for _, v := range vars {
			set(v.Key, v.Value)
		}
	}
	env := make([]string, 0, len(order))
	for _, k := range order {
		env = append(env, k+"="+values[k])
	}
	return env
}

// EnvRefs returns the distinct secret references used as whole values in
// env, as `op run` does.
func EnvRefs(env []string) []string {
	var refs []string
	for _, kv := range env {
		_, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(v, "op://") && !slices.Contains(refs, v) {
			refs = append(refs, v)
		}
	}
	return refs
}

// SubstituteEnv replaces whole-value references in env with their values.
func SubstituteEnv(env []string, values map[string]string) ([]string, error) {
	out := make([]string, len(env))
	for i, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(v, "op://") {
			resolved, ok := values[v]
			if !ok {
				return nil, fmt.Errorf("no value for %s", v)
			}
			v = resolved
		}
		out[i] = k + "=" + v
	}
	return out, nil
}

// Exec replaces the current process with argv, run with env. A bare command
// name is looked up in the PATH of env, the environment the command will
// actually run with.
func Exec(argv []string, env []string) error {
	path, err := LookPath(argv[0], env)
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, env)
}

// LookPath resolves file like a shell would with the PATH found in env.
// Relative PATH entries are skipped, so a command is never picked up from
// the current directory by accident.
func LookPath(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return file, checkExecutable(file)
	}
	var pathEnv string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathEnv = v
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, file)
		if checkExecutable(p) == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: executable file not found in PATH", file)
}

func checkExecutable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable file", path)
	}
	return nil
}
