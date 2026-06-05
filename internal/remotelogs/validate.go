package remotelogs

import (
	"fmt"
	"regexp"
)

// ValidateParams — фильтрация всех user-input полей ДО формирования shell-команды.
// Это первая линия защиты от инъекций; shellQuote в shell.go — вторая.
func ValidateParams(p Params) error {
	if !containerRe.MatchString(p.Container) {
		return fmt.Errorf("container must match %s (name or id of remote container)", containerRe.String())
	}
	if p.Tail < SentinelTailAll || p.Tail > maxTailLines {
		return fmt.Errorf("tail must be -1 (all) or 0..%d", maxTailLines)
	}
	if p.Since != "" && !sinceUntilRe.MatchString(p.Since) {
		return fmt.Errorf("since must be a duration like '30m', '2h' or RFC3339 timestamp")
	}
	if p.Until != "" && !sinceUntilRe.MatchString(p.Until) {
		return fmt.Errorf("until must be a duration like '30m', '2h' or RFC3339 timestamp")
	}
	return nil
}

const maxTailLines = 1_000_000 // верхний потолок: больше — нет смысла

var (
	// container: id (12 или 64 hex) ИЛИ имя контейнера. Имя контейнера в
	// Docker — [a-zA-Z0-9][a-zA-Z0-9_.-], длина 1..253 (мы кладём 1..255).
	containerRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$`)

	// since/until: либо duration `42s/30m/2h/3d`, либо RFC3339-подобная дата.
	// Docker принимает оба формата + локализованные ("2026-05-29 10:00:00.123 +0300").
	// Пробел внутри character class — для offset'а отдельным словом.
	sinceUntilRe = regexp.MustCompile(`^[0-9]+[smhd]$|^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.+Z \-]+$`)
)
