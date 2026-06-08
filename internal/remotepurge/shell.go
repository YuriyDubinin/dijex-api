package remotepurge

import (
	"bytes"
	"context"
	"strings"

	"golang.org/x/crypto/ssh"
)

// runSSH запускает команду в новой SSH-сессии и возвращает stdout+stderr.
// Контракт совпадает с remotedeploy/shell.go::runSSH.
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

// shellQuote — POSIX-safe одинарные кавычки (defence-in-depth поверх ValidateParams).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// firstNonEmpty возвращает первый непустой аргумент.
func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			return p
		}
	}
	return ""
}
