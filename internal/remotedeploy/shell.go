package remotedeploy

import (
	"bytes"
	"context"
	"strings"

	"golang.org/x/crypto/ssh"
)

// runSSH запускает команду в новой SSH-сессии и возвращает stdout+stderr.
// stderr читается отдельно — в Docker CLI часто полезная инфа (логин, прогресс
// pull) идёт именно туда, и при ошибке мы хотим её показать в Message шага.
func runSSH(ctx context.Context, client *ssh.Client, cmd string) (stdout, stderr string, exitErr error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()

	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	exitErr = sess.Run(cmd)
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), exitErr
}

// runSSHWithStdin — то же, что runSSH, но передаёт stdin в команду.
// Используется для `docker login --password-stdin`: пароль улетает в pipe
// процесса напрямую, в argv его НЕТ (не светится в `ps`, не пишется в логи).
func runSSHWithStdin(ctx context.Context, client *ssh.Client, cmd, stdin string) (stdout, stderr string, exitErr error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()

	sess.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	exitErr = sess.Run(cmd)
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), exitErr
}

// shellQuote оборачивает строку в одинарные кавычки для безопасной передачи
// в bash/sh. Любая внутренняя одинарная кавычка превращается в `'\''`
// (выходим из quoted, экранируем `'`, входим обратно). Это стандартный
// POSIX-safe приём.
//
// ВАЖНО: shellQuote — это вторая линия защиты ПОВЕРХ ValidateParams.
// Сама по себе она не гарантирует безопасность, если упустить регексп.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// firstNonEmpty возвращает первый непустой аргумент (полезно для message).
func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			return p
		}
	}
	return ""
}

