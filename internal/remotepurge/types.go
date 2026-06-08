// Package remotepurge выполняет цепочку «снести образ и все его контейнеры
// с удалённого сервера» через SSH. Это симметричная пара к remotedeploy:
// если deploy выкатывает образ (login → stop → rm → rmi → pull → run → verify),
// то purge — НАОБОРОТ зачищает (find → stop → rm → rmi → verify_gone).
//
// Применение: освобождение места, очистка после неудачного rollout, точечное
// «убрать всё связанное с этим image:tag».
//
// Безопасность: все пользовательские строки (image / tag / container_name)
// проходят строгие regexp ДО формирования команд (см. ValidateParams) +
// дополнительный shellQuote (defence-in-depth).
package remotepurge

import "time"

// PurgeParams — параметры одного запуска purge.
type PurgeParams struct {
	// Реквизиты registry — НЕ для логина (purge ничего не пуллит), а только
	// для сборки полной ссылки image_ref = host/namespace/image:tag.
	// Тот же image_ref должен совпадать с тем, что выкатывал deploy, иначе
	// поиск по ancestor= не найдёт контейнеры.
	RegistryHost      string // "docker.io", "ghcr.io" и т.п. (без схемы)
	RegistryNamespace string // "yuriydubinin100"

	// Образ
	Image string // "dijex-web-ui" (без namespace и тега)
	Tag   string // "1.0.0"

	// ContainerName — опциональное точное имя контейнера. Если задано, поиск
	// идёт И по имени, И по ancestor=image_ref (как в deploy). Это покрывает
	// случай «контейнер с этим именем работает с другого образа» — снесём
	// и его тоже. Если пусто — ищем только по образу.
	ContainerName string
}

// imageRef собирает каноническую ссылку: host/namespace/image:tag. Точно так
// же, как в remotedeploy.DeployParams.imageRef.
func (p PurgeParams) imageRef() string {
	ref := p.Image
	if p.RegistryNamespace != "" {
		ref = p.RegistryNamespace + "/" + ref
	}
	if p.RegistryHost != "" {
		ref = p.RegistryHost + "/" + ref
	}
	return ref + ":" + p.Tag
}

// PurgeResult — итог всей цепочки. Структура повторяет remotedeploy.DeployResult:
// фронт может использовать один и тот же компонент для отображения прогресса.
type PurgeResult struct {
	Available     bool         `json:"available"`              // удалось ли начать (docker CLI присутствует)
	Reason        string       `json:"reason,omitempty"`       // объяснение, если Available=false
	Success       bool         `json:"success"`                // все обязательные шаги завершились OK
	ImageRef      string       `json:"image_ref"`              // полная ссылка на образ, который чистили
	ContainerName string       `json:"container_name,omitempty"`
	Steps         []StepResult `json:"steps"`                  // упорядоченный список шагов
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
	DurationMS    int64        `json:"duration_ms"`
}

// StepResult — итог одного шага. Те же поля, что в remotedeploy.StepResult.
type StepResult struct {
	Name       string `json:"name"`        // машинное имя: "find_containers", "remove_image", ...
	Title      string `json:"title"`       // человекочитаемое
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
	StepFindContainers   = "find_containers"
	StepStopContainers   = "stop_containers"
	StepRemoveContainers = "remove_containers"
	StepRemoveImage      = "remove_image"
	StepVerifyPurged     = "verify_purged"
)
