package remotelogs

import (
	"context"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// tailWriter — io.Writer-«кольцевой буфер»: держит последние max байт.
// При переполнении выбрасывает старое начало (FIFO), помечает Truncated=true,
// сохраняет полную сумму записанных байт в Total. Это позволяет читать
// потенциально гигабайтные логи без OOM на стороне бэка.
type tailWriter struct {
	max       int
	buf       []byte
	Truncated bool
	Total     int64
}

func newTailWriter(max int) *tailWriter {
	return &tailWriter{max: max, buf: make([]byte, 0, min(max, 4096))}
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.Total += int64(len(p))
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	// Случай 1: один чанк больше всего буфера — берём только его хвост.
	if n >= w.max {
		w.buf = append(w.buf[:0], p[n-w.max:]...)
		w.Truncated = true
		return n, nil
	}
	// Случай 2: хвост не влезает — обрезаем старое начало.
	if len(w.buf)+n > w.max {
		keep := w.max - n
		copy(w.buf, w.buf[len(w.buf)-keep:])
		w.buf = w.buf[:keep]
		w.buf = append(w.buf, p...)
		w.Truncated = true
		return n, nil
	}
	// Случай 3: всё помещается без обрезки.
	w.buf = append(w.buf, p...)
	return n, nil
}

func (w *tailWriter) String() string {
	return string(w.buf)
}

// runDockerLogs выполняет команду docker logs в SSH-сессии и собирает
// stdout/stderr раздельно в tailWriter'ах. Возвращает оба буфера + флаги
// truncated + полные размеры + ошибку запуска (если была).
//
// Контекст проверяется до запуска (golang.org/x/crypto/ssh не поддерживает
// ctx-cancel прямо в Run). Размер каждого потока ограничен MaxLogBytes.
func runDockerLogs(ctx context.Context, client *ssh.Client, cmd string, captureStderr bool) (stdoutBuf, stderrBuf *tailWriter, exitErr error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()

	stdoutBuf = newTailWriter(MaxLogBytes)
	sess.Stdout = stdoutBuf

	if captureStderr {
		stderrBuf = newTailWriter(MaxLogBytes)
		sess.Stderr = stderrBuf
	} else {
		// Сбрасываем stderr в /dev/null — не нужен фронту, но не блокируем команду.
		sess.Stderr = io.Discard
		stderrBuf = newTailWriter(0)
	}

	exitErr = sess.Run(cmd)
	return stdoutBuf, stderrBuf, exitErr
}

// shellQuote — POSIX-safe одинарные кавычки с заменой `'` → `'\''`. Защита
// поверх ValidateParams (defence-in-depth).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// min — простая утилита (Go 1.21+ имеет встроенный, но дублируем для ясности).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
