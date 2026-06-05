package remotedeploy

import (
	"fmt"
	"regexp"
)

// ValidateParams — фильтрация ВСЕХ user-input полей. Если кто-то решит
// подсунуть `; rm -rf /` в имя контейнера, мы это отрежем ДО построения
// shell-команд. Это первая (и главная) линия защиты.
//
// Правила:
//   - image: разрешены [a-z0-9._-] и `/` (для repo внутри namespace). Длина 1–255.
//   - tag: [a-zA-Z0-9._-], первый символ — не `.` и не `-` (как требует Docker).
//   - container_name: [a-zA-Z0-9._-], первый — буквенно-цифровой. Длина 1–255.
//   - registry_host / namespace / username: [a-zA-Z0-9._-/:]. Опциональные.
//   - ports: host/container 1..65535, без дублей host-портов.
//
// Возвращает agregated-ошибку с понятным сообщением по первому невалидному полю.
func ValidateParams(p DeployParams) error {
	if !imageRefRe.MatchString(p.Image) {
		return fmt.Errorf("image must match %s", imageRefRe.String())
	}
	if !tagRe.MatchString(p.Tag) {
		return fmt.Errorf("tag must match %s and not start with '.' or '-'", tagRe.String())
	}
	if !containerNameRe.MatchString(p.ContainerName) {
		return fmt.Errorf("container_name must match %s", containerNameRe.String())
	}
	if p.RegistryHost != "" && !registryHostRe.MatchString(p.RegistryHost) {
		return fmt.Errorf("registry_host must match %s", registryHostRe.String())
	}
	if p.RegistryNamespace != "" && !namespaceRe.MatchString(p.RegistryNamespace) {
		return fmt.Errorf("registry_namespace must match %s", namespaceRe.String())
	}
	if p.RegistryUsername != "" && !usernameRe.MatchString(p.RegistryUsername) {
		return fmt.Errorf("registry_username must match %s", usernameRe.String())
	}
	if p.RestartPolicy != "" && !validRestartPolicy(p.RestartPolicy) {
		return fmt.Errorf("restart_policy must be one of: no | on-failure | always | unless-stopped")
	}
	if len(p.Ports) == 0 {
		return fmt.Errorf("at least one port mapping is required")
	}
	seenHostPorts := make(map[int]struct{}, len(p.Ports))
	for i, port := range p.Ports {
		if port.Host < 1 || port.Host > 65535 {
			return fmt.Errorf("ports[%d].host must be in 1..65535", i)
		}
		if port.Container < 1 || port.Container > 65535 {
			return fmt.Errorf("ports[%d].container must be in 1..65535", i)
		}
		if _, dup := seenHostPorts[port.Host]; dup {
			return fmt.Errorf("ports[%d].host=%d duplicates an earlier mapping", i, port.Host)
		}
		seenHostPorts[port.Host] = struct{}{}
	}
	return nil
}

// Регулярки строгие: только то, что реально встречается в Docker-нотации.
// Использован re2 (стандартный Go regexp).
var (
	// repo внутри namespace: nginx, my-app, org/sub/repo
	imageRefRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$`)

	// тег: 1-128 символов, первый не . и не -
	tagRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

	// имя контейнера: 1-255 символов, первый — alnum
	containerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$`)

	// host registry: example.com:5000, ghcr.io, registry-1.docker.io
	registryHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]{1,5})?$`)

	// namespace: yuriydubinin100, my-org, scope/sub (DockerHub только одноуровневый, но ghcr/harbor — могут многоуровневые)
	namespaceRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$`)

	// username: обычно email или alphanum; разрешим @+._-
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+@-]{0,254}$`)
)

func validRestartPolicy(s string) bool {
	switch s {
	case "no", "on-failure", "always", "unless-stopped":
		return true
	}
	return false
}
