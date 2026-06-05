package remotedeploy

import (
	"strings"
	"testing"
)

func validParams() DeployParams {
	return DeployParams{
		RegistryHost:      "docker.io",
		RegistryNamespace: "yuriydubinin100",
		RegistryUsername:  "yuriy@example.com",
		RegistryPassword:  "secret",
		Image:             "dijex-console-ui",
		Tag:               "1.0.0",
		ContainerName:     "dijex-console-ui",
		Ports:             []PortMapping{{Host: 13080, Container: 80}},
		RestartPolicy:     "unless-stopped",
	}
}

func TestValidateParams_HappyPath(t *testing.T) {
	if err := ValidateParams(validParams()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateParams_RejectsInjection(t *testing.T) {
	bad := []DeployParams{
		// Очевидные shell-инъекции
		funcMutate(validParams(), func(p *DeployParams) { p.Image = "nginx; rm -rf /" }),
		funcMutate(validParams(), func(p *DeployParams) { p.Tag = "1.0.0 && malicious" }),
		funcMutate(validParams(), func(p *DeployParams) { p.ContainerName = "x`whoami`" }),
		funcMutate(validParams(), func(p *DeployParams) { p.ContainerName = "$(echo hi)" }),
		funcMutate(validParams(), func(p *DeployParams) { p.RegistryHost = "evil.com; cat /etc/passwd" }),
		funcMutate(validParams(), func(p *DeployParams) { p.RegistryNamespace = "user/../../etc" }),
		funcMutate(validParams(), func(p *DeployParams) { p.RegistryUsername = "u'; DROP TABLE--" }),
		// Невалидные форматы
		funcMutate(validParams(), func(p *DeployParams) { p.Image = "" }),
		funcMutate(validParams(), func(p *DeployParams) { p.Tag = "" }),
		funcMutate(validParams(), func(p *DeployParams) { p.Tag = ".bad" }),
		funcMutate(validParams(), func(p *DeployParams) { p.Tag = "-bad" }),
		funcMutate(validParams(), func(p *DeployParams) { p.ContainerName = ".bad" }),
		// Порты
		funcMutate(validParams(), func(p *DeployParams) { p.Ports = nil }),
		funcMutate(validParams(), func(p *DeployParams) { p.Ports = []PortMapping{{Host: 0, Container: 80}} }),
		funcMutate(validParams(), func(p *DeployParams) { p.Ports = []PortMapping{{Host: 80, Container: 70000}} }),
		funcMutate(validParams(), func(p *DeployParams) { p.Ports = []PortMapping{{Host: 80, Container: 80}, {Host: 80, Container: 90}} }),
		funcMutate(validParams(), func(p *DeployParams) { p.RestartPolicy = "evil-policy" }),
	}
	for i, p := range bad {
		if err := ValidateParams(p); err == nil {
			t.Errorf("case %d: expected error, got nil (params=%+v)", i, p)
		}
	}
}

func TestImageRef(t *testing.T) {
	cases := []struct {
		p    DeployParams
		want string
	}{
		{validParams(), "docker.io/yuriydubinin100/dijex-console-ui:1.0.0"},
		{funcMutate(validParams(), func(p *DeployParams) { p.RegistryHost = "" }), "yuriydubinin100/dijex-console-ui:1.0.0"},
		{funcMutate(validParams(), func(p *DeployParams) {
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

func TestBuildDockerRunCommand(t *testing.T) {
	p := validParams()
	cmd := buildDockerRunCommand(p)

	// Все user-input должны быть в одинарных кавычках.
	want := []string{
		"docker run -d",
		"--name 'dijex-console-ui'",
		"-p 13080:80",
		"--restart 'unless-stopped'",
		"'docker.io/yuriydubinin100/dijex-console-ui:1.0.0'",
	}
	for _, w := range want {
		if !strings.Contains(cmd, w) {
			t.Errorf("missing fragment %q in:\n%s", w, cmd)
		}
	}
}

func TestBuildDockerRunCommand_MultiplePorts(t *testing.T) {
	p := validParams()
	p.Ports = []PortMapping{
		{Host: 8080, Container: 80},
		{Host: 8443, Container: 443},
	}
	cmd := buildDockerRunCommand(p)
	if !strings.Contains(cmd, "-p 8080:80") || !strings.Contains(cmd, "-p 8443:443") {
		t.Errorf("ports missing in:\n%s", cmd)
	}
}

func TestIsDockerHubHost(t *testing.T) {
	cases := map[string]bool{
		// DockerHub-алиасы (login должен идти без host'а):
		"":                       true,
		"docker.io":               true,
		"index.docker.io":         true,
		"registry-1.docker.io":    true,
		"registry.hub.docker.com": true,
		// С пробелами/регистром — тоже должны распознаваться:
		" docker.io ":            true,
		"REGISTRY-1.DOCKER.IO":   true,
		// Приватные/сторонние — login идёт с host'ом:
		"ghcr.io":                       false,
		"registry.gitlab.com":           false,
		"harbor.example.com":            false,
		"example.com:5000":              false,
		"123456789.dkr.ecr.us-east-1.amazonaws.com": false,
	}
	for in, want := range cases {
		if got := isDockerHubHost(in); got != want {
			t.Errorf("isDockerHubHost(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestSanitizeRegistryPassword(t *testing.T) {
	cases := map[string]string{
		// Без изменений — чистый пароль:
		"dckr_pat_xyz":  "dckr_pat_xyz",
		"normalP@ssw0rd": "normalP@ssw0rd",
		// Trailing CRLF (классический случай copy-paste из терминала):
		"dckr_pat_xyz\n":     "dckr_pat_xyz",
		"dckr_pat_xyz\r\n":   "dckr_pat_xyz",
		"dckr_pat_xyz\n\n":   "dckr_pat_xyz",
		"dckr_pat_xyz\r":     "dckr_pat_xyz",
		"dckr_pat_xyz\t":     "dckr_pat_xyz",
		"dckr_pat_xyz  ":     "dckr_pat_xyz",
		"dckr_pat_xyz \n\r": "dckr_pat_xyz",
		// Пустые после trim — должны стать пустыми:
		"":        "",
		"\n":      "",
		"\r\n":    "",
		"   ":     "",
	}
	for in, want := range cases {
		if got := sanitizeRegistryPassword(in); got != want {
			t.Errorf("sanitizeRegistryPassword(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestContainsControlChar(t *testing.T) {
	cases := map[string]bool{
		"dckr_pat_xyz":         false,
		"P@ssw0rd!":            false,
		"":                     false,
		"pass\nword":           true, // newline в середине
		"pass\rword":           true, // CR в середине
		"pass\tword":           true, // tab в середине
		"\n":                   true, // только control
		"a\rb\nc\td":           true,
	}
	for in, want := range cases {
		if got := containsControlChar(in); got != want {
			t.Errorf("containsControlChar(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"hello":         "'hello'",
		"with space":    "'with space'",
		"with'quote":    `'with'\''quote'`,
		"a'b'c":         `'a'\''b'\''c'`,
		";rm -rf /":     "';rm -rf /'",
		"$(evil)":       "'$(evil)'",
		"`backticks`":   "'`backticks`'",
		`"double"`:      `'"double"'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q)=%q, want %q", in, got, want)
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

func TestInitialSteps_OrderAndCount(t *testing.T) {
	steps := initialSteps()
	want := []string{
		StepRegistryLogin, StepStopExisting, StepRemoveExisting,
		StepRemoveImage, StepPullImage, StepRunContainer, StepVerifyRunning,
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
	if steps[0].Status != StatusOK {
		t.Errorf("a touched: %v", steps[0])
	}
	if steps[1].Status != StatusFailed {
		t.Errorf("b touched: %v", steps[1])
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
		t.Errorf("expected allOK=true for all ok/skipped")
	}
	withFailed := append([]StepResult{}, ok...)
	withFailed = append(withFailed, StepResult{Status: StatusFailed})
	if allOK(withFailed) {
		t.Errorf("failed step should make allOK=false")
	}
	withNotRun := append([]StepResult{}, ok...)
	withNotRun = append(withNotRun, StepResult{Status: StatusNotRun})
	if allOK(withNotRun) {
		t.Errorf("not_run step should make allOK=false")
	}
}

func funcMutate(p DeployParams, fn func(*DeployParams)) DeployParams {
	fn(&p)
	return p
}
