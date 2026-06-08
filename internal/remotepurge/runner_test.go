package remotepurge

import (
	"testing"
)

func validParams() PurgeParams {
	return PurgeParams{
		RegistryHost:      "docker.io",
		RegistryNamespace: "yuriydubinin100",
		Image:             "dijex-console-ui",
		Tag:               "1.0.0",
		ContainerName:     "dijex-console-ui",
	}
}

func TestValidateParams_HappyPath(t *testing.T) {
	if err := ValidateParams(validParams()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// без container_name тоже валидно — purge можно делать только по образу
	if err := ValidateParams(funcMutate(validParams(), func(p *PurgeParams) { p.ContainerName = "" })); err != nil {
		t.Errorf("missing container_name must be valid: %v", err)
	}
}

func TestValidateParams_RejectsInjection(t *testing.T) {
	bad := []PurgeParams{
		funcMutate(validParams(), func(p *PurgeParams) { p.Image = "nginx; rm -rf /" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.Tag = "1.0.0 && bad" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.ContainerName = "x`whoami`" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.ContainerName = "$(echo hi)" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.RegistryHost = "evil.com; cat /etc/passwd" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.RegistryNamespace = "user/../../etc" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.Image = "" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.Tag = "" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.Tag = ".bad" }),
		funcMutate(validParams(), func(p *PurgeParams) { p.Tag = "-bad" }),
	}
	for i, p := range bad {
		if err := ValidateParams(p); err == nil {
			t.Errorf("case %d: expected error, got nil (params=%+v)", i, p)
		}
	}
}

func TestImageRef(t *testing.T) {
	cases := []struct {
		p    PurgeParams
		want string
	}{
		{validParams(), "docker.io/yuriydubinin100/dijex-console-ui:1.0.0"},
		{funcMutate(validParams(), func(p *PurgeParams) { p.RegistryHost = "" }), "yuriydubinin100/dijex-console-ui:1.0.0"},
		{funcMutate(validParams(), func(p *PurgeParams) {
			p.RegistryHost = "ghcr.io"
			p.RegistryNamespace = "team/sub"
			p.Image = "api"
			p.Tag = "v2"
		}), "ghcr.io/team/sub/api:v2"},
	}
	for _, c := range cases {
		if got := c.p.imageRef(); got != c.want {
			t.Errorf("imageRef=%q, want %q", got, c.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"hello":      "'hello'",
		"with space": "'with space'",
		"a'b":        `'a'\''b'`,
		"$(evil)":    "'$(evil)'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestInitialSteps_OrderAndCount(t *testing.T) {
	steps := initialSteps()
	want := []string{
		StepFindContainers, StepStopContainers, StepRemoveContainers,
		StepRemoveImage, StepVerifyPurged,
	}
	if len(steps) != len(want) {
		t.Fatalf("steps count=%d, want %d", len(steps), len(want))
	}
	for i, s := range steps {
		if s.Name != want[i] {
			t.Errorf("steps[%d].Name=%q, want %q", i, s.Name, want[i])
		}
		if s.Status != StatusNotRun {
			t.Errorf("steps[%d].Status=%q, want %q", i, s.Status, StatusNotRun)
		}
	}
}

func TestMarkRemainingNotRun(t *testing.T) {
	steps := []StepResult{
		{Name: "a", Status: StatusOK},
		{Name: "b", Status: StatusFailed},
		{Name: "c", Status: StatusNotRun},
		{Name: "d", Status: StatusNotRun},
	}
	markRemainingNotRun(steps, "b")
	if steps[0].Status != StatusOK || steps[1].Status != StatusFailed {
		t.Errorf("a/b touched: %+v", steps[:2])
	}
	for _, s := range steps[2:] {
		if s.Status != StatusNotRun {
			t.Errorf("%s.Status=%v, want not_run", s.Name, s.Status)
		}
	}
}

func TestAllOK(t *testing.T) {
	ok := []StepResult{{Status: StatusOK}, {Status: StatusOK}, {Status: StatusSkipped}}
	if !allOK(ok) {
		t.Errorf("ok+skipped → allOK=true")
	}
	withFailed := append([]StepResult{}, ok...)
	withFailed = append(withFailed, StepResult{Status: StatusFailed})
	if allOK(withFailed) {
		t.Errorf("failed must break allOK")
	}
	withNotRun := append([]StepResult{}, ok...)
	withNotRun = append(withNotRun, StepResult{Status: StatusNotRun})
	if allOK(withNotRun) {
		t.Errorf("not_run must break allOK")
	}
}

func TestIsHardStopError(t *testing.T) {
	cases := map[string]bool{
		"":                                                  false,
		"Error response from daemon: No such container: x":  false,
		"Container abc is not running":                      false,
		"docker: permission denied while connecting to":     true,
		"Cannot connect to the Docker daemon":               true,
	}
	for in, want := range cases {
		if got := isHardStopError(in); got != want {
			t.Errorf("isHardStopError(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestShortID(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"abc":                           "abc",
		"sha256:abc1234567890def123456": "abc123456789",
		"abc1234567890def":              "abc123456789",
	}
	for in, want := range cases {
		if got := shortID(in); got != want {
			t.Errorf("shortID(%q)=%q, want %q", in, got, want)
		}
	}
}

func funcMutate(p PurgeParams, fn func(*PurgeParams)) PurgeParams {
	fn(&p)
	return p
}
