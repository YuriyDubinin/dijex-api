// Package remotelogs читает логи Docker-контейнера на удалённом сервере
// через SSH и команду `docker logs`. Возвращает stdout/stderr контейнера
// раздельно (т.к. SSH-сессия их разводит). Поддерживает опции tail/since/
// until/timestamps и кольцевой буфер на N байт (защита от гигабайтных логов).
//
// Принципы:
//   - Available=false с понятным Reason, если контейнер не найден или docker
//     CLI недоступен.
//   - Best-effort: ошибка чтения stderr не валит весь ответ.
//   - Никаких изменений на удалённом сервере (только read-only `docker logs`).
package remotelogs

import "time"

// Params — параметры одного запроса логов.
type Params struct {
	// Container — id (короткий/полный) ИЛИ имя контейнера на удалённом хосте.
	// Валидируется в ValidateParams.
	Container string

	// Tail управляет числом последних строк:
	//   0  → дефолт (LastNLinesDefault строк, защита от случайного «все логи»);
	//   N>0 → последние N строк;
	//   -1 → все строки (`--tail all`).
	Tail int

	// Since/Until — опциональные фильтры по времени. Docker принимает либо
	// duration ("30m", "2h"), либо RFC3339 timestamp ("2026-05-29T10:00:00Z").
	// Валидируется как «duration ИЛИ ISO-дата».
	Since string
	Until string

	// Timestamps — добавлять ли префикс времени к каждой строке (`--timestamps`).
	Timestamps bool

	// IncludeStderr — собирать ли stderr контейнера. По умолчанию true.
	IncludeStderr bool
}

// LastNLinesDefault — сколько последних строк отдаётся, если Tail=0.
// 10000 — разумный компромисс между «достаточно для диагностики» и «не съест
// все 10 МБ потолка размера».
const LastNLinesDefault = 10000

// MaxLogBytes — потолок размера каждого потока (stdout/stderr) в байтах.
// Если контейнер выдал больше — берём ХВОСТ (последние MaxLogBytes байт),
// потому что самое свежее обычно важнее. Truncated=true.
const MaxLogBytes = 10 * 1024 * 1024 // 10 МБ

// Result — итог одного запроса логов.
type Result struct {
	Available bool   `json:"available"`         // удалось ли начать чтение
	Reason    string `json:"reason,omitempty"`  // причина, если Available=false

	Container string `json:"container"`         // эхо запроса
	Command   string `json:"command"`           // команда, выполненная на удалённой машине (без секретов)

	Stdout string `json:"stdout"`               // stdout контейнера, может быть пустым
	Stderr string `json:"stderr,omitempty"`     // stderr контейнера, может быть пустым

	BytesStdout int64 `json:"bytes_stdout"`     // полный объём stdout (до обрезки)
	BytesStderr int64 `json:"bytes_stderr"`     // полный объём stderr

	TruncatedStdout bool `json:"truncated_stdout"` // true, если BytesStdout > MaxLogBytes
	TruncatedStderr bool `json:"truncated_stderr"` // true, если BytesStderr > MaxLogBytes

	CollectedAt time.Time `json:"collected_at"`
	DurationMS  int64     `json:"duration_ms"`
}

// SentinelTailAll — значение Tail, означающее «все строки» (передаётся как
// --tail all в docker logs). 0 — НЕ all (это дефолт LastNLinesDefault).
const SentinelTailAll = -1
