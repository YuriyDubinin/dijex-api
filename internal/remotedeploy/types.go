// Package remotedeploy выполняет цепочку «выкатить новый Docker-образ на
// удалённый сервер» через SSH. Каждый деплой — это упорядоченная серия шагов
// (login → stop → rm → rmi → pull → run → verify); каждый шаг рапортует свой
// статус. При критическом сбое цепочка прерывается, оставшиеся шаги помечаются
// `skipped`.
//
// Пакет НЕ держит состояние между запусками: Runner stateless, всё нужное
// передаётся через DeployParams + живой *ssh.Client.
//
// Безопасность:
//   - Все пользовательские строки (image / tag / container_name) валидируются
//     по строгим regexp ДО формирования команд (см. ValidateParams).
//   - Аргументы для shell оборачиваются в одинарные кавычки через shellQuote
//     (defence-in-depth: даже если бы регексп пропустил спецсимвол, кавычки
//     обезвредят его в bash).
//   - Пароль для `docker login` передаётся через STDIN сессии SSH
//     (--password-stdin), а не через argv — в `ps` его не видно.
package remotedeploy

import "time"

// DeployParams — всё, что нужно одному запуску деплоя.
type DeployParams struct {
	// Реквизиты registry (см. ValidateParams). Если RegistryUsername пуст,
	// шаг registry_login пропускается (публичный registry).
	RegistryHost     string // например "docker.io" или "ghcr.io" (без схемы)
	RegistryNamespace string // например "yuriydubinin100"
	RegistryUsername string // login
	RegistryPassword string // расшифровка из БД, передаётся в stdin SSH-сессии
	RegistryInsecure bool   // позволяет http (для self-hosted) — отражается в имени реестра

	// Образ и контейнер
	Image         string // "dijex-console-ui" (без namespace и без тега)
	Tag           string // "1.0.0"
	ContainerName string // имя контейнера на удалённом хосте
	Ports         []PortMapping
	RestartPolicy string // "no" | "on-failure" | "always" | "unless-stopped"; пусто = не задавать
}

type PortMapping struct {
	Host      int
	Container int
}

// imageRef собирает каноническую ссылку: <host>/<namespace>/<image>:<tag>.
// Для DockerHub host обычно "docker.io" — но Docker CLI принимает и без host
// (тогда добавляет docker.io автоматически); явный host надёжнее для других
// реестров и для логина.
func (p DeployParams) imageRef() string {
	ref := p.Image
	if p.RegistryNamespace != "" {
		ref = p.RegistryNamespace + "/" + ref
	}
	if p.RegistryHost != "" {
		ref = p.RegistryHost + "/" + ref
	}
	return ref + ":" + p.Tag
}

// DeployResult — итог всей цепочки.
type DeployResult struct {
	Available     bool         `json:"available"`         // удалось ли вообще начать (docker CLI присутствует)
	Reason        string       `json:"reason,omitempty"`  // объяснение, если Available=false
	Success       bool         `json:"success"`           // все обязательные шаги завершились OK
	ImageRef      string       `json:"image_ref"`         // полная ссылка на образ, который мы выкатывали
	ContainerName string       `json:"container_name"`
	ContainerID   string       `json:"container_id,omitempty"` // ID запущенного контейнера (если шаг run прошёл)
	Steps         []StepResult `json:"steps"`             // упорядоченный список шагов
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
	DurationMS    int64        `json:"duration_ms"`
}

// StepResult — итог одного шага.
type StepResult struct {
	Name       string `json:"name"`        // машинное имя: "registry_login", "pull_image", ...
	Title      string `json:"title"`       // человекочитаемое: "Логин в registry"
	Status     string `json:"status"`      // ok | skipped | failed | not_run
	Message    string `json:"message"`     // что произошло
	DurationMS int64  `json:"duration_ms"` // длительность шага
}

const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusFailed  = "failed"
	StatusNotRun  = "not_run"
)

// Имена шагов — стабильные, на них завязан UI.
const (
	StepRegistryLogin  = "registry_login"
	StepStopExisting   = "stop_existing"
	StepRemoveExisting = "remove_existing"
	StepRemoveImage    = "remove_image"
	StepPullImage      = "pull_image"
	StepRunContainer   = "run_container"
	StepVerifyRunning  = "verify_running"
)
