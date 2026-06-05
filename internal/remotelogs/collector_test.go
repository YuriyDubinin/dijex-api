package remotelogs

import (
	"strings"
	"testing"
)

func validParams() Params {
	return Params{
		Container:     "my-nginx",
		Tail:          0,
		IncludeStderr: true,
	}
}

func TestValidateParams_HappyPath(t *testing.T) {
	if err := ValidateParams(validParams()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// id (12 hex)
	if err := ValidateParams(Params{Container: "abc123456789"}); err != nil {
		t.Errorf("id 12-hex must be valid: %v", err)
	}
	// id (64 hex)
	if err := ValidateParams(Params{Container: strings.Repeat("a", 64)}); err != nil {
		t.Errorf("id 64-hex must be valid: %v", err)
	}
	// tail=-1 ("all"), tail=N
	if err := ValidateParams(Params{Container: "x", Tail: SentinelTailAll}); err != nil {
		t.Errorf("tail=-1 (all) must be valid: %v", err)
	}
	if err := ValidateParams(Params{Container: "x", Tail: 5000}); err != nil {
		t.Errorf("tail=5000 must be valid: %v", err)
	}
	// since/until
	for _, ok := range []string{"30m", "2h", "42s", "5d", "2026-05-29T10:00:00Z", "2026-05-29 10:00:00.123 +0300"} {
		if err := ValidateParams(Params{Container: "x", Since: ok}); err != nil {
			t.Errorf("since=%q must be valid: %v", ok, err)
		}
	}
}

func TestValidateParams_RejectsInjection(t *testing.T) {
	bad := []Params{
		// shell-инъекции в container
		{Container: "; rm -rf /"},
		{Container: "$(whoami)"},
		{Container: "x`id`"},
		{Container: "x && y"},
		// невалидные имена
		{Container: ""},
		{Container: ".starts-with-dot"},
		{Container: "-starts-with-dash"},
		{Container: "two words"},
		// невалидный tail
		{Container: "x", Tail: -2},
		{Container: "x", Tail: maxTailLines + 1},
		// невалидный since/until
		{Container: "x", Since: "; bad"},
		{Container: "x", Until: "yesterday"},
		{Container: "x", Since: "30 minutes ago"},
	}
	for i, p := range bad {
		if err := ValidateParams(p); err == nil {
			t.Errorf("case %d expected error, got nil (params=%+v)", i, p)
		}
	}
}

func TestBuildDockerLogsCommand(t *testing.T) {
	cases := []struct {
		name     string
		params   Params
		mustHave []string
		mustNot  []string
	}{
		{
			name:     "default_tail",
			params:   Params{Container: "my-nginx"},
			mustHave: []string{"docker logs", "--tail 10000", "'my-nginx'"},
			mustNot:  []string{"--since", "--until", "--timestamps"},
		},
		{
			name:     "tail_n",
			params:   Params{Container: "my-nginx", Tail: 200},
			mustHave: []string{"--tail 200"},
		},
		{
			name:     "tail_all",
			params:   Params{Container: "my-nginx", Tail: SentinelTailAll},
			mustHave: []string{"--tail all"},
		},
		{
			name:     "with_since_until_ts",
			params:   Params{Container: "my-nginx", Since: "30m", Until: "5m", Timestamps: true},
			mustHave: []string{"--since '30m'", "--until '5m'", "--timestamps", "'my-nginx'"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := buildDockerLogsCommand(tc.params)
			for _, h := range tc.mustHave {
				if !strings.Contains(cmd, h) {
					t.Errorf("missing %q in cmd:\n%s", h, cmd)
				}
			}
			for _, n := range tc.mustNot {
				if strings.Contains(cmd, n) {
					t.Errorf("unexpected %q in cmd:\n%s", n, cmd)
				}
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":      "'plain'",
		"with space": "'with space'",
		"a'b":        `'a'\''b'`,
		";rm -rf /":  "';rm -rf /'",
		"$(evil)":    "'$(evil)'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestTailWriter_NoOverflow(t *testing.T) {
	w := newTailWriter(100)
	_, _ = w.Write([]byte("hello"))
	_, _ = w.Write([]byte(" world"))
	if w.String() != "hello world" {
		t.Errorf("got %q", w.String())
	}
	if w.Truncated {
		t.Errorf("should not be truncated")
	}
	if w.Total != 11 {
		t.Errorf("Total=%d, want 11", w.Total)
	}
}

func TestTailWriter_OverflowMultipleWrites(t *testing.T) {
	w := newTailWriter(10) // макс 10 байт
	_, _ = w.Write([]byte("AAAAA"))     // 5 байт — влезает (5/10)
	_, _ = w.Write([]byte("BBBBB"))     // ещё 5 — влезает ровно (10/10)
	_, _ = w.Write([]byte("CCCCC"))     // ещё 5 — должен выкинуть первые 5 AAAAA
	if w.String() != "BBBBBCCCCC" {
		t.Errorf("got %q, want %q", w.String(), "BBBBBCCCCC")
	}
	if !w.Truncated {
		t.Errorf("must be truncated")
	}
	if w.Total != 15 {
		t.Errorf("Total=%d, want 15", w.Total)
	}
}

func TestTailWriter_SingleHugeWrite(t *testing.T) {
	w := newTailWriter(5)
	_, _ = w.Write([]byte("ABCDEFGHIJ")) // 10 байт за раз, лимит 5
	if w.String() != "FGHIJ" {
		t.Errorf("got %q, want %q (last 5 of input)", w.String(), "FGHIJ")
	}
	if !w.Truncated {
		t.Errorf("must be truncated")
	}
	if w.Total != 10 {
		t.Errorf("Total=%d, want 10", w.Total)
	}
}
