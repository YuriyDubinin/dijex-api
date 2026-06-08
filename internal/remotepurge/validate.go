package remotepurge

import (
	"fmt"
	"regexp"
)

// ValidateParams — фильтрация всех user-input полей. Регексы те же, что в
// remotedeploy/validate.go (image / tag / container_name / registry_host /
// namespace), чтобы пара методов deploy ↔ purge принимала одинаковые формы.
func ValidateParams(p PurgeParams) error {
	if !imageRefRe.MatchString(p.Image) {
		return fmt.Errorf("image must match %s", imageRefRe.String())
	}
	if !tagRe.MatchString(p.Tag) {
		return fmt.Errorf("tag must match %s and not start with '.' or '-'", tagRe.String())
	}
	if p.ContainerName != "" && !containerNameRe.MatchString(p.ContainerName) {
		return fmt.Errorf("container_name must match %s", containerNameRe.String())
	}
	if p.RegistryHost != "" && !registryHostRe.MatchString(p.RegistryHost) {
		return fmt.Errorf("registry_host must match %s", registryHostRe.String())
	}
	if p.RegistryNamespace != "" && !namespaceRe.MatchString(p.RegistryNamespace) {
		return fmt.Errorf("registry_namespace must match %s", namespaceRe.String())
	}
	return nil
}

var (
	imageRefRe      = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$`)
	tagRe           = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	containerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$`)
	registryHostRe  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]{1,5})?$`)
	namespaceRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$`)
)
