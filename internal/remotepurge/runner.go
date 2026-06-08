package remotepurge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Runner выполняет цепочку шагов purge. Stateless — безопасен для конкурентного
// использования.
type Runner struct{}

func NewRunner() *Runner { return &Runner{} }

// Run выполняет полный цикл: find → stop → rm → rmi → verify.
// Никогда не возвращает ошибку — все проблемы кладутся в шаги.
//
// Контракт «строго последовательно»: если шаг отмечен failed, остальные шаги
// получают статус not_run. Шаги, у которых нечего делать (нет контейнеров,
// нет образа) — skipped, цепочка продолжается (это нормально для purge —
// «нечего удалять» = успех).
func (r *Runner) Run(ctx context.Context, client *ssh.Client, params PurgeParams) *PurgeResult {
	started := time.Now()
	res := &PurgeResult{
		ImageRef:      params.imageRef(),
		ContainerName: params.ContainerName,
		StartedAt:     started.UTC(),
		Steps:         initialSteps(),
	}

	// Шаг 0 (не показываем как отдельный): проверка наличия docker CLI.
	if out, _, err := runSSH(ctx, client, "command -v docker"); err != nil || out == "" {
		res.Available = false
		res.Reason = "docker CLI not found on remote host"
		markAllNotRun(res.Steps)
		finalize(res, started)
		return res
	}
	res.Available = true

	// 1. find_containers + 2. stop_containers
	existingIDs := r.stepFindContainers(ctx, client, params, findStep(res, StepFindContainers))
	if findStep(res, StepFindContainers).Status == StatusFailed {
		markRemainingNotRun(res.Steps, StepFindContainers)
		finalize(res, started)
		return res
	}
	if !r.stepStopContainers(ctx, client, existingIDs, findStep(res, StepStopContainers)) {
		markRemainingNotRun(res.Steps, StepStopContainers)
		finalize(res, started)
		return res
	}

	// 3. remove_containers
	if !r.stepRemoveContainers(ctx, client, existingIDs, findStep(res, StepRemoveContainers)) {
		markRemainingNotRun(res.Steps, StepRemoveContainers)
		finalize(res, started)
		return res
	}

	// 4. remove_image — критично для purge (без него операция не имеет смысла),
	// но образа может не быть на хосте, и это OK (skipped).
	r.stepRemoveImage(ctx, client, params, findStep(res, StepRemoveImage))
	if findStep(res, StepRemoveImage).Status == StatusFailed {
		markRemainingNotRun(res.Steps, StepRemoveImage)
		finalize(res, started)
		return res
	}

	// 5. verify_purged — финальная проверка: ни контейнеров, ни образа не осталось.
	r.stepVerifyPurged(ctx, client, params, findStep(res, StepVerifyPurged))

	res.Success = allOK(res.Steps)
	finalize(res, started)
	return res
}

// ───────────────────────── шаги ─────────────────────────

// stepFindContainers ищет контейнеры по ancestor=image_ref И (опционально) по
// точному имени. Возвращает дедуплицированный список ID. failed только при
// серьёзной проблеме с docker CLI (а не при «нет таких контейнеров»).
func (r *Runner) stepFindContainers(ctx context.Context, client *ssh.Client, p PurgeParams, step *StepResult) []string {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	ids := findExistingContainerIDs(ctx, client, p)
	if len(ids) == 0 {
		step.Status = StatusSkipped
		step.Message = "no containers found for " + p.imageRef()
		return nil
	}
	step.Status = StatusOK
	step.Message = fmt.Sprintf("found %d container(s): %s", len(ids), strings.Join(shortIDs(ids), ", "))
	return ids
}

func (r *Runner) stepStopContainers(ctx context.Context, client *ssh.Client, ids []string, step *StepResult) bool {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	if len(ids) == 0 {
		step.Status = StatusSkipped
		step.Message = "no containers to stop"
		return true
	}
	cmd := "docker stop " + strings.Join(quoteAll(ids), " ")
	_, stderr, err := runSSH(ctx, client, cmd)
	if err != nil && isHardStopError(stderr) {
		step.Status = StatusFailed
		step.Message = "docker stop failed: " + firstNonEmpty(stderr, err.Error())
		return false
	}
	step.Status = StatusOK
	step.Message = fmt.Sprintf("stopped %d container(s)", len(ids))
	return true
}

func (r *Runner) stepRemoveContainers(ctx context.Context, client *ssh.Client, ids []string, step *StepResult) bool {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	if len(ids) == 0 {
		step.Status = StatusSkipped
		step.Message = "no containers to remove"
		return true
	}
	cmd := "docker rm -f " + strings.Join(quoteAll(ids), " ")
	_, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		step.Status = StatusFailed
		step.Message = "docker rm failed: " + firstNonEmpty(stderr, err.Error())
		return false
	}
	step.Status = StatusOK
	step.Message = fmt.Sprintf("removed %d container(s)", len(ids))
	return true
}

// stepRemoveImage удаляет образ. Используем `docker rmi -f` всегда: пользователь
// может иметь несколько тегов одного image (тогда rmi без -f падает с
// "image is referenced in multiple repositories"). Force-флаг здесь корректен,
// потому что весь смысл purge — гарантированно убрать конкретный image:tag.
func (r *Runner) stepRemoveImage(ctx context.Context, client *ssh.Client, p PurgeParams, step *StepResult) {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	ref := p.imageRef()
	// Сначала смотрим, есть ли образ — это избавляет от шумных «не найдено».
	checkCmd := "docker image inspect " + shellQuote(ref) + " >/dev/null 2>&1"
	if _, _, err := runSSH(ctx, client, checkCmd); err != nil {
		step.Status = StatusSkipped
		step.Message = "image not present on host"
		return
	}
	cmd := "docker rmi -f " + shellQuote(ref)
	_, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		step.Status = StatusFailed
		step.Message = "docker rmi failed: " + firstNonEmpty(stderr, err.Error())
		return
	}
	step.Status = StatusOK
	step.Message = "removed image " + ref
}

// stepVerifyPurged финально проверяет: контейнеров с этим image нет, и сам
// образ не присутствует. Если что-то осталось — failed.
func (r *Runner) stepVerifyPurged(ctx context.Context, client *ssh.Client, p PurgeParams, step *StepResult) {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	// 1) Контейнеров быть не должно.
	remaining := findExistingContainerIDs(ctx, client, p)
	if len(remaining) > 0 {
		step.Status = StatusFailed
		step.Message = fmt.Sprintf("containers still present: %s", strings.Join(shortIDs(remaining), ", "))
		return
	}
	// 2) Образа быть не должно.
	checkCmd := "docker image inspect " + shellQuote(p.imageRef()) + " >/dev/null 2>&1"
	if _, _, err := runSSH(ctx, client, checkCmd); err == nil {
		// inspect отработал успешно → образ всё ещё есть.
		step.Status = StatusFailed
		step.Message = "image still present on host: " + p.imageRef()
		return
	}
	step.Status = StatusOK
	step.Message = "no containers and no image remain"
}

// ───────────────────────── helpers ─────────────────────────

func initialSteps() []StepResult {
	return []StepResult{
		{Name: StepFindContainers, Title: "Поиск контейнеров", Status: StatusNotRun},
		{Name: StepStopContainers, Title: "Остановка контейнеров", Status: StatusNotRun},
		{Name: StepRemoveContainers, Title: "Удаление контейнеров", Status: StatusNotRun},
		{Name: StepRemoveImage, Title: "Удаление образа", Status: StatusNotRun},
		{Name: StepVerifyPurged, Title: "Проверка очистки", Status: StatusNotRun},
	}
}

func findStep(res *PurgeResult, name string) *StepResult {
	for i := range res.Steps {
		if res.Steps[i].Name == name {
			return &res.Steps[i]
		}
	}
	panic("remotepurge: step not found: " + name)
}

func markAllNotRun(steps []StepResult) {
	for i := range steps {
		if steps[i].Status == "" {
			steps[i].Status = StatusNotRun
		}
	}
}

func markRemainingNotRun(steps []StepResult, failedName string) {
	passed := false
	for i := range steps {
		if !passed {
			if steps[i].Name == failedName {
				passed = true
			}
			continue
		}
		if steps[i].Status == StatusNotRun || steps[i].Status == "" {
			steps[i].Status = StatusNotRun
		}
	}
}

func allOK(steps []StepResult) bool {
	for _, s := range steps {
		if s.Status == StatusFailed || s.Status == StatusNotRun {
			return false
		}
	}
	return true
}

func finalize(res *PurgeResult, started time.Time) {
	res.FinishedAt = time.Now().UTC()
	res.DurationMS = res.FinishedAt.Sub(started).Milliseconds()
}

// findExistingContainerIDs ищет по имени И по образу (как в remotedeploy).
func findExistingContainerIDs(ctx context.Context, client *ssh.Client, p PurgeParams) []string {
	var sources []string
	if p.ContainerName != "" {
		out, _, _ := runSSH(ctx, client,
			"docker ps -a --filter "+shellQuote("name=^"+p.ContainerName+"$")+" -q --no-trunc")
		sources = append(sources, out)
	}
	out, _, _ := runSSH(ctx, client,
		"docker ps -a --filter "+shellQuote("ancestor="+p.imageRef())+" -q --no-trunc")
	sources = append(sources, out)

	seen := make(map[string]struct{})
	var ids []string
	for _, src := range sources {
		for _, line := range strings.Split(src, "\n") {
			id := strings.TrimSpace(line)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// isHardStopError отличает реальные ошибки stop от безобидных «уже остановлен».
func isHardStopError(stderr string) bool {
	s := strings.ToLower(stderr)
	if strings.Contains(s, "is not running") || strings.Contains(s, "no such container") {
		return false
	}
	return s != ""
}

func shortID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func shortIDs(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = shortID(id)
	}
	return out
}

func quoteAll(items []string) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = shellQuote(it)
	}
	return out
}
