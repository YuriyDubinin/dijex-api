package service

import (
	"time"

	"github.com/google/uuid"

	"github.com/YuriyDubinin/dijex-api/internal/docker"
	"github.com/YuriyDubinin/dijex-api/internal/remotedeploy"
	"github.com/YuriyDubinin/dijex-api/internal/remoteinfo"
	"github.com/YuriyDubinin/dijex-api/internal/remotelogs"
	"github.com/YuriyDubinin/dijex-api/internal/remotepurge"
	"github.com/YuriyDubinin/dijex-api/internal/systemd"
)

// CreateServerInput — данные создания сервера. Секреты — в открытом виде,
// шифруются в сервисе. Пустые поля допустимы (детали можно задать позже).
type CreateServerInput struct {
	Name                 string
	Host                 string
	Port                 int
	Protocol             string
	Username             string
	AuthMethod           string
	Password             string
	PrivateKey           string
	PrivateKeyPassphrase string
	Description          string
	Environment          string
	Provider             string
	Location             string
	Tags                 []string
}

// UpdateServerInput — полное обновление. Секреты — указатели:
//   nil   → оставить текущий;
//   ""    → очистить;
//   "..." → задать новый (шифруется).
type UpdateServerInput struct {
	ID                   uuid.UUID
	Name                 string
	Host                 string
	Port                 int
	Protocol             string
	Username             string
	AuthMethod           string
	Password             *string
	PrivateKey           *string
	PrivateKeyPassphrase *string
	Description          string
	Environment          string
	Provider             string
	Location             string
	Tags                 []string
	IsActive             bool
}

type ListServersInput struct {
	Page        int
	PageSize    int
	Environment string
	Protocol    string
	AuthMethod  string
	IsActive    *bool
	Search      string
	SortBy      string
	Order       string
}

// ServerView — представление сервера наружу. Секреты НЕ отдаются — только
// флаги has_password / has_private_key.
type ServerView struct {
	ID         uuid.UUID
	Name       string
	Host       string
	Port       int
	Protocol   string
	Username   string
	AuthMethod string

	Description string
	Environment string
	Provider    string
	Location    string
	Tags        []string

	OS               string
	OSVersion        string
	Arch             string
	KernelVersion    string
	RemoteHostname   string
	CPUCores         *int
	MemoryTotalBytes *int64
	DiskTotalBytes   *int64

	// Гео-факты, собранные при /api/servers/remote/connect.
	RemotePublicIP string
	CountryCode    string // ISO 3166-1 alpha-2, например "RU"
	Country        string // английское имя страны, например "Russia"

	HasPassword   bool
	HasPrivateKey bool

	IsActive        bool
	SSHKeyInstalled bool
	LastCheckedAt   *time.Time
	LastStatus      string

	CreatedAt time.Time
	UpdatedAt time.Time
}

type ListServersOutput struct {
	Items      []ServerView
	Pagination Pagination
}

type DeleteServerOutput struct {
	ID        uuid.UUID
	DeletedAt time.Time
}

type RemoteConnectOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string // publickey | password
	Status    string // OK | AUTH_FAILED | UNREACHABLE | TIMEOUT | ERROR
	Message   string
	CheckedAt time.Time

	// Факты (если собрались при успешном подключении).
	RemoteHostname string
	OS             string
	KernelVersion  string
	Arch           string
	CPUCores       *int
	RemotePublicIP string
	CountryCode    string
	Country        string
}

type RemotePingOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	IsActive  bool
	CheckedAt time.Time
}

// ───────────────────────── Deploy ─────────────────────────

// DeployInput — входные данные для деплоя образа на удалённый сервер.
// ServerID + RegistryID указывают, КУДА деплоить и ОТКУДА брать образ;
// остальные поля описывают сам образ и параметры запуска контейнера.
type DeployInput struct {
	ServerID      uuid.UUID
	RegistryID    uuid.UUID
	Image         string
	Tag           string
	ContainerName string
	Ports         []DeployPort
	RestartPolicy string
}

type DeployPort struct {
	Host      int
	Container int
}

// DeployOutput — итог деплоя. По стандартному шаблону: id сервера + connected +
// status + message. Сам отчёт по шагам лежит в Result (если SSH удался).
type DeployOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	Result *remotedeploy.DeployResult // присутствует при Connected=true
}

// ───────────────────────── Purge image ─────────────────────────

// PurgeImageInput — параметры зачистки образа на удалённом сервере.
// Симметрично DeployInput: registry_id + image + tag для построения image_ref,
// плюс опциональное container_name (если нужно ловить контейнер по имени).
type PurgeImageInput struct {
	ServerID      uuid.UUID
	RegistryID    uuid.UUID
	Image         string
	Tag           string
	ContainerName string // опционально
}

// PurgeImageOutput — итог. Структурно идентичен DeployOutput.
type PurgeImageOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	Result *remotepurge.PurgeResult // присутствует при Connected=true
}

// ───────────────────────── Container logs ─────────────────────────

// RemoteLogsInput — параметры запроса логов контейнера.
type RemoteLogsInput struct {
	ServerID      uuid.UUID
	Container     string
	Tail          int
	Since         string
	Until         string
	Timestamps    bool
	IncludeStderr bool
}

// RemoteLogsOutput — оболочка над логами контейнера. Logs nil-able: если
// SSH не получилось — отдаём connected=false + причину.
type RemoteLogsOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	Logs *remotelogs.Result // только при Connected=true
}

// RemoteImagesOutput — оболочка над списком Docker-образов удалённого сервера.
type RemoteImagesOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	Images *docker.ImagesInfo // только при Connected=true
}

// RemoteContainersOutput — оболочка над списком контейнеров удалённого сервера.
// Containers nil-able: если SSH не получилось — отдаём connected=false + причину.
type RemoteContainersOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	Containers *docker.ContainersInfo // только при Connected=true
}

// RemoteServicesOutput — оболочка над списком systemd-сервисов удалённого сервера.
type RemoteServicesOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	Services *systemd.ServicesInfo // только при Connected=true
}

// RemoteSystemInfoOutput — оболочка над снимком удалённого сервера.
// Сама секция System nil-able: если SSH-коннект не удался, фронт получит
// Connected=false + Status/Message, без System.
type RemoteSystemInfoOutput struct {
	ID        uuid.UUID
	Connected bool
	Method    string
	Status    string
	Message   string
	CheckedAt time.Time

	System *remoteinfo.RemoteSystemInfo // только при Connected=true
}

// InstallSSHKeyOutput — итог установки нашего ключа на удалённый сервер.
type InstallSSHKeyOutput struct {
	ID               uuid.UUID
	Connected        bool      // удалось залогиниться по паролю
	AlreadyInstalled bool      // ключ уже был в authorized_keys
	Installed        bool      // ключ дописали в authorized_keys
	Verified         bool      // ключевая аутентификация прошла после установки
	SSHKeyInstalled  bool      // флаг в БД после операции (true ↔ Verified=true)
	Status           string    // OK | AUTH_FAILED | UNREACHABLE | TIMEOUT | ERROR
	Message          string
	CheckedAt        time.Time
}
