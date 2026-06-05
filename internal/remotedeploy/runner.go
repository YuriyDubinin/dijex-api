package remotedeploy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Runner выполняет цепочку шагов деплоя. Stateless — безопасен для конкурентного
// использования (несколько одновременных деплоев на разные серверы).
type Runner struct{}

func NewRunner() *Runner { return &Runner{} }

// Run выполняет полный цикл: login → stop → rm → rmi → pull → run → verify.
// Возвращает DeployResult с детальным отчётом по каждому шагу. Никогда не
// возвращает ошибку — все проблемы кладутся в шаги.
//
// Контракт «строго последовательно»: если шаг отмечен failed, остальные шаги
// получают статус not_run. Шаги, у которых нечего делать (нет старых
// контейнеров, нет старого образа) — skipped, цепочка продолжается.
func (r *Runner) Run(ctx context.Context, client *ssh.Client, params DeployParams) *DeployResult {
	started := time.Now()
	res := &DeployResult{
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

	// 1. registry_login
	if !r.stepLogin(ctx, client, params, findStep(res, StepRegistryLogin)) {
		markRemainingNotRun(res.Steps, StepRegistryLogin)
		finalize(res, started)
		return res
	}

	// 2. stop_existing  + 3. remove_existing
	existingIDs := r.stepFindAndStop(ctx, client, params, findStep(res, StepStopExisting))
	if findStep(res, StepStopExisting).Status == StatusFailed {
		markRemainingNotRun(res.Steps, StepStopExisting)
		finalize(res, started)
		return res
	}
	if !r.stepRemoveContainers(ctx, client, existingIDs, findStep(res, StepRemoveExisting)) {
		markRemainingNotRun(res.Steps, StepRemoveExisting)
		finalize(res, started)
		return res
	}

	// 4. remove_image (best-effort: если образа нет — skipped, не падаем)
	r.stepRemoveImage(ctx, client, params, findStep(res, StepRemoveImage))

	// 5. pull_image (критично: если упало — стоп)
	if !r.stepPull(ctx, client, params, findStep(res, StepPullImage)) {
		markRemainingNotRun(res.Steps, StepPullImage)
		finalize(res, started)
		return res
	}

	// 6. run_container (критично)
	if !r.stepRun(ctx, client, params, findStep(res, StepRunContainer), res) {
		markRemainingNotRun(res.Steps, StepRunContainer)
		finalize(res, started)
		return res
	}

	// 7. verify_running (критично — без этого не считаем деплой успешным)
	r.stepVerify(ctx, client, params, findStep(res, StepVerifyRunning), res)

	res.Success = allOK(res.Steps)
	finalize(res, started)
	return res
}

// ───────────────────────── шаги ─────────────────────────

// stepLogin: docker login через --password-stdin. Если username/password не
// заданы — пропускаем (публичный registry). Возвращает true, если можно
// продолжать (либо успешно вошли, либо нечего делать).
func (r *Runner) stepLogin(ctx context.Context, client *ssh.Client, p DeployParams, step *StepResult) bool {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	// Защита defence-in-depth (первый trim делает сервис). Здесь повторяем,
	// чтобы инвариант «пароль уходит в stdin без trailing CRLF/whitespace»
	// держался независимо от того, кто вызывает Runner.
	password := sanitizeRegistryPassword(p.RegistryPassword)

	if p.RegistryUsername == "" || password == "" {
		step.Status = StatusSkipped
		step.Message = "no credentials in registry record — assuming public access"
		return true
	}

	// Если внутри пароля остался \r или \n ПОСЛЕ trim'а — это однозначно
	// битый ввод (пароль с переносом строки в середине). docker login такой
	// пароль обработает, но registry вернёт «malformed Authorization header».
	// Лучше остановиться сразу с понятной диагностикой.
	if containsControlChar(password) {
		step.Status = StatusFailed
		step.Message = "registry password contains control characters (CR/LF/tab) — re-save the registry credentials"
		return false
	}

	host := p.RegistryHost
	if host == "" {
		host = "docker.io"
	}

	// DockerHub case-sensitive по username при `docker login --password-stdin`
	// с обычным паролем: вход с "YuriyDubinin100" получает `malformed HTTP
	// Authorization header`, вход с "yuriydubinin100" — Login Succeeded. На
	// стороне DockerHub username всегда хранится в lowercase, поэтому
	// принудительный lower-case безопасен и идемпотентен. Для других registry
	// case может быть значим (например, в самописных Harbor), поэтому
	// нормализуем username ТОЛЬКО для DockerHub-хостов.
	username := p.RegistryUsername
	if isDockerHubHost(host) {
		username = strings.ToLower(username)
	}

	// ВАЖНО для DockerHub: команда `docker login` с явно указанным V2-registry-
	// хостом (registry-1.docker.io) идёт по неправильному code-path и получает
	// ответ «malformed HTTP Authorization header» от registry. Правильный путь
	// — НЕ указывать host: тогда CLI логинит в дефолтный index.docker.io/v1/
	// (legacy login endpoint). Image-pull/push по-прежнему может ходить на
	// registry-1.docker.io/... — docker CLI сам мапит credentials между этими
	// двумя именами в одной DockerHub-зоне. См. issue moby/moby#10866.
	var cmd string
	if isDockerHubHost(host) {
		cmd = fmt.Sprintf("docker login -u %s --password-stdin", shellQuote(username))
	} else {
		cmd = fmt.Sprintf("docker login %s -u %s --password-stdin", shellQuote(host), shellQuote(username))
	}
	_, stderr, err := runSSHWithStdin(ctx, client, cmd, password)
	if err != nil {
		step.Status = StatusFailed
		step.Message = "docker login failed: " + firstNonEmpty(stderr, err.Error())
		return false
	}
	step.Status = StatusOK
	step.Message = "logged in to " + host
	return true
}

// isDockerHubHost распознаёт алиасы DockerHub. Login на этих хостах надо
// делать БЕЗ явного указания host (см. комментарий в stepLogin).
// Список замкнутый: только реально используемые DockerHub-имена.
func isDockerHubHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "",
		"docker.io",
		"index.docker.io",
		"registry-1.docker.io",
		"registry.hub.docker.com":
		return true
	}
	return false
}

// sanitizeRegistryPassword обрезает trailing whitespace и CRLF у пароля.
// Это критично для `docker login --password-stdin`: оно само обрезает только
// ОДИН trailing \n, остаток уходит в Authorization header и ломает запрос.
func sanitizeRegistryPassword(pw string) string {
	return strings.TrimRight(pw, "\r\n\t ")
}

// containsControlChar возвращает true, если строка содержит \r, \n или \t
// в любой позиции. Используется как поздняя страховка: после sanitize любые
// такие символы означают «они внутри пароля», что почти всегда — битый ввод.
func containsControlChar(s string) bool {
	return strings.ContainsAny(s, "\r\n\t")
}

// stepFindAndStop: находит контейнеры по имени и по образу, останавливает их.
// Возвращает список ID для последующего удаления.
func (r *Runner) stepFindAndStop(ctx context.Context, client *ssh.Client, p DeployParams, step *StepResult) []string {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	ids := findExistingContainerIDs(ctx, client, p)
	if len(ids) == 0 {
		step.Status = StatusSkipped
		step.Message = "no existing containers found"
		return nil
	}

	cmd := "docker stop " + strings.Join(quoteAll(ids), " ")
	_, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		// Контейнер может быть уже остановлен — это не фейл. Но если stderr
		// содержит реальную ошибку (No such container и т.п.) — отметим failed.
		if isHardStopError(stderr) {
			step.Status = StatusFailed
			step.Message = "docker stop failed: " + firstNonEmpty(stderr, err.Error())
			return ids
		}
	}
	step.Status = StatusOK
	step.Message = fmt.Sprintf("stopped %d container(s): %s", len(ids), strings.Join(shortIDs(ids), ", "))
	return ids
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

// stepRemoveImage: best-effort удаление образа с тем же тегом. Если образа
// нет — это нормально (первый деплой), помечаем skipped и продолжаем.
func (r *Runner) stepRemoveImage(ctx context.Context, client *ssh.Client, p DeployParams, step *StepResult) {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	ref := p.imageRef()
	// Сначала проверим, есть ли образ — это избавляет от шумных «не найдено» в логах.
	checkCmd := "docker image inspect " + shellQuote(ref) + " >/dev/null 2>&1"
	if _, _, err := runSSH(ctx, client, checkCmd); err != nil {
		step.Status = StatusSkipped
		step.Message = "image not present on host"
		return
	}
	cmd := "docker rmi -f " + shellQuote(ref)
	_, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		// Если образ используется другим контейнером — это всё ещё проблема,
		// но не фатальная: pull новой версии создаст другой слой и run возможен.
		// Отметим failed только если pull нам это потом «зацепит» — на этом
		// этапе достаточно warning'а через message с прежним статусом ok.
		step.Status = StatusSkipped
		step.Message = "rmi reported issue (continuing): " + firstNonEmpty(stderr, err.Error())
		return
	}
	step.Status = StatusOK
	step.Message = "removed image " + ref
}

func (r *Runner) stepPull(ctx context.Context, client *ssh.Client, p DeployParams, step *StepResult) bool {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	ref := p.imageRef()
	cmd := "docker pull " + shellQuote(ref)
	_, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		step.Status = StatusFailed
		step.Message = "docker pull failed: " + firstNonEmpty(stderr, err.Error())
		return false
	}
	step.Status = StatusOK
	step.Message = "pulled " + ref
	return true
}

func (r *Runner) stepRun(ctx context.Context, client *ssh.Client, p DeployParams, step *StepResult, res *DeployResult) bool {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	cmd := buildDockerRunCommand(p)
	stdout, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		step.Status = StatusFailed
		step.Message = "docker run failed: " + firstNonEmpty(stderr, err.Error())
		return false
	}
	// docker run -d печатает container ID в stdout — это удобно для логов.
	containerID := strings.TrimSpace(stdout)
	res.ContainerID = containerID
	step.Status = StatusOK
	if containerID != "" {
		step.Message = "container started: " + shortID(containerID)
	} else {
		step.Message = "container started"
	}
	return true
}

// stepVerify проверяет, что контейнер действительно запустился (State.Running=true)
// и не упал сразу. Между run и verify имеет смысл небольшая пауза для контейнеров,
// которые крашатся за миллисекунды после старта (bad entrypoint, опечатка в env).
func (r *Runner) stepVerify(ctx context.Context, client *ssh.Client, p DeployParams, step *StepResult, res *DeployResult) {
	t := time.Now()
	defer func() { step.DurationMS = time.Since(t).Milliseconds() }()

	// Пауза 1с, чтобы быстро-крашащиеся контейнеры успели проявить себя.
	select {
	case <-time.After(time.Second):
	case <-ctx.Done():
		step.Status = StatusFailed
		step.Message = "verification cancelled: " + ctx.Err().Error()
		return
	}

	cmd := "docker inspect -f '{{.State.Running}}|{{.State.ExitCode}}|{{.State.Status}}' " + shellQuote(p.ContainerName)
	stdout, stderr, err := runSSH(ctx, client, cmd)
	if err != nil {
		step.Status = StatusFailed
		step.Message = "docker inspect failed: " + firstNonEmpty(stderr, err.Error())
		return
	}
	parts := strings.SplitN(stdout, "|", 3)
	if len(parts) < 3 {
		step.Status = StatusFailed
		step.Message = "unexpected inspect output: " + stdout
		return
	}
	running := parts[0] == "true"
	exitCode := parts[1]
	state := parts[2]
	if !running {
		step.Status = StatusFailed
		step.Message = fmt.Sprintf("container is not running (state=%s, exit_code=%s)", state, exitCode)
		return
	}
	step.Status = StatusOK
	step.Message = "container is running"
}

// ───────────────────────── helpers ─────────────────────────

func initialSteps() []StepResult {
	return []StepResult{
		{Name: StepRegistryLogin, Title: "Логин в registry", Status: StatusNotRun},
		{Name: StepStopExisting, Title: "Остановка существующих контейнеров", Status: StatusNotRun},
		{Name: StepRemoveExisting, Title: "Удаление существующих контейнеров", Status: StatusNotRun},
		{Name: StepRemoveImage, Title: "Удаление старого образа", Status: StatusNotRun},
		{Name: StepPullImage, Title: "Загрузка нового образа", Status: StatusNotRun},
		{Name: StepRunContainer, Title: "Запуск контейнера", Status: StatusNotRun},
		{Name: StepVerifyRunning, Title: "Проверка работоспособности", Status: StatusNotRun},
	}
}

func findStep(res *DeployResult, name string) *StepResult {
	for i := range res.Steps {
		if res.Steps[i].Name == name {
			return &res.Steps[i]
		}
	}
	// Не должно случиться — initialSteps содержит все.
	panic("remotedeploy: step not found: " + name)
}

func markAllNotRun(steps []StepResult) {
	for i := range steps {
		if steps[i].Status == "" {
			steps[i].Status = StatusNotRun
		}
	}
}

// markRemainingNotRun — после провального шага все, кто ещё не запускался,
// помечаются not_run (а не failed: они не запускались, не их вина).
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
		if s.Status == StatusFailed {
			return false
		}
		if s.Status == StatusNotRun {
			return false
		}
	}
	return true
}

func finalize(res *DeployResult, started time.Time) {
	res.FinishedAt = time.Now().UTC()
	res.DurationMS = res.FinishedAt.Sub(started).Milliseconds()
}

// findExistingContainerIDs: ищет контейнеры по точному имени И по образу.
// Точное совпадение по имени — фильтром "^<name>$" (regex anchor).
// Объединяет результаты, дедуплицирует.
func findExistingContainerIDs(ctx context.Context, client *ssh.Client, p DeployParams) []string {
	// По имени
	byName, _, _ := runSSH(ctx, client, "docker ps -a --filter "+shellQuote("name=^"+p.ContainerName+"$")+" -q --no-trunc")
	// По образу (ancestor совпадает по любому тегу того же image_ref)
	byImage, _, _ := runSSH(ctx, client, "docker ps -a --filter "+shellQuote("ancestor="+p.imageRef())+" -q --no-trunc")

	seen := make(map[string]struct{})
	var out []string
	for _, src := range []string{byName, byImage} {
		for _, line := range strings.Split(src, "\n") {
			id := strings.TrimSpace(line)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// isHardStopError отличает реальные ошибки stop от безобидных "уже остановлен".
// Docker возвращает ненулевой exit code в обоих случаях, поэтому смотрим текст.
func isHardStopError(stderr string) bool {
	s := strings.ToLower(stderr)
	// Безобидные:
	//   "No such container: xxx" — кто-то уже удалил, продолжим
	//   "Container ... is not running" — уже стопнут
	if strings.Contains(s, "is not running") || strings.Contains(s, "no such container") {
		return false
	}
	return s != ""
}

// shortID — 12 hex, как делает docker.
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

// buildDockerRunCommand собирает безопасную команду `docker run -d ...`.
// Все user-input проходят через shellQuote. Параметры заранее валидированы.
func buildDockerRunCommand(p DeployParams) string {
	parts := []string{"docker", "run", "-d"}
	parts = append(parts, "--name", shellQuote(p.ContainerName))
	for _, port := range p.Ports {
		parts = append(parts, "-p", strconv.Itoa(port.Host)+":"+strconv.Itoa(port.Container))
	}
	if p.RestartPolicy != "" {
		parts = append(parts, "--restart", shellQuote(p.RestartPolicy))
	}
	parts = append(parts, shellQuote(p.imageRef()))
	return strings.Join(parts, " ")
}
