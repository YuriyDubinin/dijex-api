package remotelogs

import (
	"context"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Collector — сборщик логов контейнера с удалённого сервера. Stateless,
// безопасен для конкурентного использования.
type Collector struct{}

func NewCollector() *Collector { return &Collector{} }

// Collect выполняет `docker logs ...` на удалённой машине через SSH.
// Никогда не возвращает ошибку — все проблемы кладутся в Result
// (Available=false + Reason). Параметры считаются предварительно
// провалидированными вызывающим (см. ValidateParams).
func (c *Collector) Collect(ctx context.Context, client *ssh.Client, p Params) *Result {
	started := time.Now()
	res := &Result{
		Container:   p.Container,
		CollectedAt: started.UTC(),
	}
	defer func() {
		res.DurationMS = time.Since(started).Milliseconds()
	}()

	// Проверка наличия docker CLI до сборки команды.
	if out, _, err := runProbeDocker(ctx, client); err != nil || out == "" {
		res.Available = false
		res.Reason = "docker CLI not found on remote host"
		return res
	}

	cmd := buildDockerLogsCommand(p)
	res.Command = cmd

	stdout, stderr, exitErr := runDockerLogs(ctx, client, cmd, p.IncludeStderr)

	res.Stdout = stdout.String()
	res.BytesStdout = stdout.Total
	res.TruncatedStdout = stdout.Truncated
	if p.IncludeStderr {
		res.Stderr = stderr.String()
		res.BytesStderr = stderr.Total
		res.TruncatedStderr = stderr.Truncated
	}

	if exitErr != nil {
		// Классические сбои docker logs: контейнер не найден, нет прав, демон лежит.
		stderrText := strings.ToLower(res.Stderr)
		switch {
		case strings.Contains(stderrText, "no such container"):
			res.Available = false
			res.Reason = "container not found: " + p.Container
		case strings.Contains(stderrText, "permission denied"):
			res.Available = false
			res.Reason = "permission denied — user lacks docker access (add to 'docker' group)"
		case strings.Contains(stderrText, "cannot connect to the docker daemon"):
			res.Available = false
			res.Reason = "docker daemon is not running on remote host"
		default:
			// docker logs может вернуть exit code != 0 при battle-tested ошибках,
			// которые мы не распознали, но при этом полезный stdout/stderr уже
			// собран. Считаем «available, но что-то странное» — фронт увидит
			// stderr с деталями.
			res.Available = true
			res.Reason = "docker logs exited with error: " + exitErr.Error()
		}
		return res
	}

	res.Available = true
	return res
}

// runProbeDocker — лёгкая проверка, что на удалённой машине есть docker CLI.
// Никаких side-effects.
func runProbeDocker(ctx context.Context, client *ssh.Client) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()
	out, runErr := sess.Output("command -v docker 2>/dev/null")
	if runErr != nil && len(out) == 0 {
		return "", "", runErr
	}
	return strings.TrimSpace(string(out)), "", nil
}

// buildDockerLogsCommand собирает безопасную команду docker logs со всеми
// опциями. Все user-input проходят через shellQuote. Параметры заранее
// провалидированы.
func buildDockerLogsCommand(p Params) string {
	parts := []string{"docker", "logs"}

	tail := p.Tail
	if tail == 0 {
		tail = LastNLinesDefault
	}
	if tail == SentinelTailAll {
		parts = append(parts, "--tail", "all")
	} else {
		parts = append(parts, "--tail", strconv.Itoa(tail))
	}

	if p.Since != "" {
		parts = append(parts, "--since", shellQuote(p.Since))
	}
	if p.Until != "" {
		parts = append(parts, "--until", shellQuote(p.Until))
	}
	if p.Timestamps {
		parts = append(parts, "--timestamps")
	}

	parts = append(parts, shellQuote(p.Container))
	return strings.Join(parts, " ")
}
