package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"golang.org/x/crypto/ssh"

	"github.com/YuriyDubinin/dijex-api/internal/docker"
	"github.com/YuriyDubinin/dijex-api/internal/domain"
	"github.com/YuriyDubinin/dijex-api/internal/geo"
	"github.com/YuriyDubinin/dijex-api/internal/remotedeploy"
	"github.com/YuriyDubinin/dijex-api/internal/remoteinfo"
	"github.com/YuriyDubinin/dijex-api/internal/sshclient"
	"github.com/YuriyDubinin/dijex-api/internal/sshkey"
	"github.com/YuriyDubinin/dijex-api/internal/systemd"
	"github.com/YuriyDubinin/dijex-api/pkg/crypto"
)

// serverConnector — узкий контракт SSH-подключения. Реализуется *sshclient.Connector.
type serverConnector interface {
	Connect(ctx context.Context, t sshclient.Target) sshclient.Result
	Ping(ctx context.Context, t sshclient.Target) sshclient.Result
	InstallPublicKey(ctx context.Context, t sshclient.Target, publicKey string) sshclient.InstallResult
	// Dial открывает SSH-соединение и возвращает живой клиент для нескольких
	// последовательных сессий (например, сбор расширенного снимка системы).
	// Caller обязан закрыть клиент. На неуспех — (nil, "", failResult).
	Dial(ctx context.Context, t sshclient.Target) (*ssh.Client, string, sshclient.Result)
}

// remoteSystemCollector — узкий контракт сбора снимка удалённой системы.
// Реализуется *remoteinfo.Collector. nil допустим (тогда метод RemoteSystemInfo
// вернёт ошибку конфигурации).
type remoteSystemCollector interface {
	Collect(ctx context.Context, client *ssh.Client, conn remoteinfo.ConnectionInfo) *remoteinfo.RemoteSystemInfo
}

// remoteContainersCollector — контракт сбора списка контейнеров удалённого
// сервера. Реализуется *remotedocker.Collector. nil допустим — тогда метод
// RemoteContainers вернёт ошибку конфигурации.
type remoteContainersCollector interface {
	Collect(ctx context.Context, client *ssh.Client) *docker.ContainersInfo
}

// remoteImagesCollector — контракт сбора Docker-образов удалённого сервера.
// Реализуется *remotedocker.Collector (метод CollectImages). nil допустим.
type remoteImagesCollector interface {
	CollectImages(ctx context.Context, client *ssh.Client) *docker.ImagesInfo
}

// remoteServicesCollector — контракт сбора systemd-сервисов удалённого
// сервера. Реализуется *remotesystemd.Collector. nil допустим.
type remoteServicesCollector interface {
	Collect(ctx context.Context, client *ssh.Client) *systemd.ServicesInfo
}

// remoteDeployer — контракт выполнения деплоя на удалённый сервер.
// Реализуется *remotedeploy.Runner. nil допустим — тогда метод Deploy вернёт
// ошибку конфигурации.
type remoteDeployer interface {
	Run(ctx context.Context, client *ssh.Client, params remotedeploy.DeployParams) *remotedeploy.DeployResult
}

// serverKeyProvider — контракт получения публичного ключа приложения.
// Реализуется *sshkey.Manager.
type serverKeyProvider interface {
	Check(ctx context.Context) (sshkey.KeyInfo, error)
}

// geoResolver — контракт резолвинга страны по IP. Реализуется *geo.Resolver.
// Допускается nil — тогда гео-факты просто не заполняются (не ошибка).
type geoResolver interface {
	Lookup(ip string) (geo.CountryInfo, bool)
}

const (
	defaultServerPageSize = 20
	maxServerPageSize     = 100
	defaultSSHPort        = 22
	maxServerTags         = 30
	maxServerTagLen       = 50
)

type ServerService struct {
	repo             domain.ServerRepository
	registryRepo     domain.RegistryRepository // используется методом Deploy
	cipher           *crypto.Cipher
	connector        serverConnector
	keys             serverKeyProvider
	geo              geoResolver               // nil допустим
	systemRemote     remoteSystemCollector     // nil допустим
	containersRemote remoteContainersCollector // nil допустим
	imagesRemote     remoteImagesCollector     // nil допустим
	servicesRemote   remoteServicesCollector   // nil допустим
	deployer         remoteDeployer            // nil допустим
	logger           *slog.Logger
	clock            func() time.Time
}

func NewServerService(
	repo domain.ServerRepository,
	registryRepo domain.RegistryRepository,
	cipher *crypto.Cipher,
	connector serverConnector,
	keys serverKeyProvider,
	geoRes geoResolver,
	systemRemote remoteSystemCollector,
	containersRemote remoteContainersCollector,
	imagesRemote remoteImagesCollector,
	servicesRemote remoteServicesCollector,
	deployer remoteDeployer,
	logger *slog.Logger,
) *ServerService {
	return &ServerService{
		repo:             repo,
		registryRepo:     registryRepo,
		cipher:           cipher,
		connector:        connector,
		keys:             keys,
		geo:              geoRes,
		systemRemote:     systemRemote,
		containersRemote: containersRemote,
		imagesRemote:     imagesRemote,
		servicesRemote:   servicesRemote,
		deployer:         deployer,
		logger:           logger,
		clock:            time.Now,
	}
}

// RemoteConnect подключается к серверу по SSH (наш ключ → пароль), проверяет
// сессию и собирает базовые факты. Недоступность/отказ auth — НЕ ошибка метода:
// возвращается Output с Connected=false. is_active НЕ трогаем (это делает Ping).
func (s *ServerService) RemoteConnect(ctx context.Context, id uuid.UUID) (*RemoteConnectOutput, error) {
	srv, password, err := s.loadServerForSSH(ctx, id)
	if err != nil {
		return nil, err
	}

	res := s.connector.Connect(ctx, sshclient.Target{
		Host:     srv.Host,
		Port:     srv.Port,
		User:     srv.Username,
		Password: password,
	})

	now := s.clock()
	errMsg := ""
	if !res.Connected {
		errMsg = res.Message
	}
	// connect не управляет is_active — только фиксирует статус попытки.
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, res.Status, errMsg, now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}

	out := &RemoteConnectOutput{
		ID:        id,
		Connected: res.Connected,
		Method:    res.Method,
		Status:    res.Status,
		Message:   res.Message,
		CheckedAt: now,
	}
	if res.Connected && res.Facts != nil {
		facts := domain.ServerFacts{
			OS:             res.Facts.OS,
			Arch:           res.Facts.Arch,
			KernelVersion:  res.Facts.KernelVersion,
			RemoteHostname: res.Facts.Hostname,
			RemotePublicIP: res.Facts.PublicIP,
		}
		if res.Facts.CPUCores > 0 {
			cores := res.Facts.CPUCores
			facts.CPUCores = &cores
		}
		// Резолвим страну ЛОКАЛЬНО по публичному IP, увиденному сервером.
		// Если ip пустой/приватный/нет в базе — поля остаются пустыми (ok=false).
		if s.geo != nil && facts.RemotePublicIP != "" {
			if ci, ok := s.geo.Lookup(facts.RemotePublicIP); ok {
				facts.CountryCode = ci.Code
				facts.Country = ci.Name
			}
		}
		if ferr := s.repo.UpdateFacts(ctx, id, facts); ferr != nil {
			s.logger.Warn("update server facts", "err", ferr, "server_id", id)
		}
		out.RemoteHostname = res.Facts.Hostname
		out.OS = res.Facts.OS
		out.KernelVersion = res.Facts.KernelVersion
		out.Arch = res.Facts.Arch
		out.CPUCores = facts.CPUCores
		out.RemotePublicIP = facts.RemotePublicIP
		out.CountryCode = facts.CountryCode
		out.Country = facts.Country
	}

	s.logger.Info("server remote connect", "server_id", id, "status", res.Status, "method", res.Method, "connected", res.Connected)
	return out, nil
}

// RemotePing пингует SSH-соединение и выставляет is_active: успех → true,
// провал → false (в обе стороны).
func (s *ServerService) RemotePing(ctx context.Context, id uuid.UUID) (*RemotePingOutput, error) {
	srv, password, err := s.loadServerForSSH(ctx, id)
	if err != nil {
		return nil, err
	}

	res := s.connector.Ping(ctx, sshclient.Target{
		Host:     srv.Host,
		Port:     srv.Port,
		User:     srv.Username,
		Password: password,
	})

	now := s.clock()
	errMsg := ""
	if !res.Connected {
		errMsg = res.Message
	}
	active := res.Connected
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, res.Status, errMsg, now, &active); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}

	s.logger.Info("server remote ping", "server_id", id, "status", res.Status, "connected", res.Connected, "is_active", active)
	return &RemotePingOutput{
		ID:        id,
		Connected: res.Connected,
		Method:    res.Method,
		Status:    res.Status,
		Message:   res.Message,
		IsActive:  active,
		CheckedAt: now,
	}, nil
}

// RemoteSystemInfo открывает SSH-соединение и собирает подробный снимок
// удалённого сервера (host/cpu/memory/disks/network/docker). По форме данных
// эндпоинт максимально близок к локальному /api/system/main, чтобы фронт
// рендерил их теми же компонентами.
//
// Недоступность сервера / ошибки auth — НЕ ошибка метода: возвращается
// Output с Connected=false и пустым System; фронт отрисует ту же ошибку,
// что и в /remote/connect.
//
// is_active НЕ трогаем — этот метод диагностический, не управляющий.
func (s *ServerService) RemoteSystemInfo(ctx context.Context, id uuid.UUID) (*RemoteSystemInfoOutput, error) {
	if s.systemRemote == nil {
		return nil, fmt.Errorf("server: remote system collector is not configured")
	}

	// Для system/main нам нужно ещё и время handshake'а — поэтому считаем
	// латентность вручную вокруг openRemoteSession, не используя его наполовину.
	srv, password, err := s.loadServerForSSH(ctx, id)
	if err != nil {
		return nil, err
	}
	dialStart := s.clock()
	client, method, failRes := s.connector.Dial(ctx, sshclient.Target{
		Host:     srv.Host,
		Port:     srv.Port,
		User:     srv.Username,
		Password: password,
	})
	if client == nil {
		now := s.clock()
		if uerr := s.repo.UpdateConnectionStatus(ctx, id, failRes.Status, failRes.Message, now, nil); uerr != nil {
			s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
		}
		s.logger.Info("server remote system info", "server_id", id, "status", failRes.Status, "connected", false)
		return &RemoteSystemInfoOutput{
			ID: id, Connected: false, Status: failRes.Status, Message: failRes.Message, CheckedAt: now,
		}, nil
	}
	defer client.Close()
	latencyMS := s.clock().Sub(dialStart).Milliseconds()

	conn := remoteinfo.ConnectionInfo{
		Host:      srv.Host,
		Port:      srv.Port,
		User:      srv.Username,
		Method:    method,
		LatencyMS: latencyMS,
	}
	system := s.systemRemote.Collect(ctx, client, conn)

	now := s.clock()
	// Запишем статус подключения как успех — мы реально вошли и собрали данные.
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, sshclient.StatusOK, "", now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}

	s.logger.Info("server remote system info",
		"server_id", id, "status", sshclient.StatusOK, "method", method, "connected", true,
		"sections_with_errors", len(system.Errors), "duration_ms", system.CollectionDurationMS,
	)

	return &RemoteSystemInfoOutput{
		ID:        id,
		Connected: true,
		Method:    method,
		Status:    sshclient.StatusOK,
		Message:   "system info collected via " + method,
		CheckedAt: now,
		System:    system,
	}, nil
}

// RemoteContainers возвращает список контейнеров с удалённого сервера через
// SSH + CLI `docker`. JSON-форма ответа эквивалентна /api/system/containers.
// is_active не трогаем — метод диагностический.
func (s *ServerService) RemoteContainers(ctx context.Context, id uuid.UUID) (*RemoteContainersOutput, error) {
	if s.containersRemote == nil {
		return nil, fmt.Errorf("server: remote containers collector is not configured")
	}
	client, method, failRes, err := s.openRemoteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		now := s.clock()
		s.logger.Info("server remote containers", "server_id", id, "status", failRes.Status, "connected", false)
		return &RemoteContainersOutput{
			ID: id, Connected: false, Status: failRes.Status, Message: failRes.Message, CheckedAt: now,
		}, nil
	}
	defer client.Close()

	info := s.containersRemote.Collect(ctx, client)

	now := s.clock()
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, sshclient.StatusOK, "", now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}
	s.logger.Info("server remote containers",
		"server_id", id, "status", sshclient.StatusOK, "method", method, "connected", true,
		"count", info.Count, "available", info.Available,
	)
	return &RemoteContainersOutput{
		ID:         id,
		Connected:  true,
		Method:     method,
		Status:     sshclient.StatusOK,
		Message:    "containers collected via " + method,
		CheckedAt:  now,
		Containers: info,
	}, nil
}

// RemoteImages возвращает список Docker-образов с удалённого сервера через
// SSH + CLI `docker image inspect`. JSON-форма ответа эквивалентна
// /api/system/images. is_active не трогаем — метод диагностический.
func (s *ServerService) RemoteImages(ctx context.Context, id uuid.UUID) (*RemoteImagesOutput, error) {
	if s.imagesRemote == nil {
		return nil, fmt.Errorf("server: remote images collector is not configured")
	}
	client, method, failRes, err := s.openRemoteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		now := s.clock()
		s.logger.Info("server remote images", "server_id", id, "status", failRes.Status, "connected", false)
		return &RemoteImagesOutput{
			ID: id, Connected: false, Status: failRes.Status, Message: failRes.Message, CheckedAt: now,
		}, nil
	}
	defer client.Close()

	info := s.imagesRemote.CollectImages(ctx, client)

	now := s.clock()
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, sshclient.StatusOK, "", now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}
	s.logger.Info("server remote images",
		"server_id", id, "status", sshclient.StatusOK, "method", method, "connected", true,
		"count", info.Count, "available", info.Available,
	)
	return &RemoteImagesOutput{
		ID:        id,
		Connected: true,
		Method:    method,
		Status:    sshclient.StatusOK,
		Message:   "images collected via " + method,
		CheckedAt: now,
		Images:    info,
	}, nil
}

// Deploy выкатывает указанный образ из registry на удалённый сервер. Цепочка:
// docker login → стоп существующих контейнеров → их удаление → удаление
// старого образа → pull нового → docker run → verify. Каждый шаг рапортует
// статус; при критическом сбое остальные шаги получают status=not_run.
//
// Возвращает ошибку метода ТОЛЬКО при проблемах конфигурации/валидации
// (нет сервера/registry в БД, невалидные параметры). Сетевые проблемы, отказ
// auth, упавшие шаги — это 200 OK с подробностями в Output.
func (s *ServerService) Deploy(ctx context.Context, in DeployInput) (*DeployOutput, error) {
	if s.deployer == nil {
		return nil, fmt.Errorf("server: deployer is not configured")
	}

	// 1) Валидация входа (id + параметры самого деплоя).
	if in.ServerID == uuid.Nil {
		return nil, domain.ValidationErrors{
			&domain.ValidationError{Field: "server_id", Message: "is required"},
		}
	}
	if in.RegistryID == uuid.Nil {
		return nil, domain.ValidationErrors{
			&domain.ValidationError{Field: "registry_id", Message: "is required"},
		}
	}

	// 2) Загружаем registry, расшифровываем пароль.
	reg, err := s.registryRepo.GetByID(ctx, in.RegistryID)
	if err != nil {
		return nil, err // domain.ErrNotFound оборачивает не-found
	}
	regPassword := ""
	if reg.PasswordEncrypted != "" {
		pw, derr := s.cipher.Decrypt(reg.PasswordEncrypted)
		if derr != nil {
			return nil, fmt.Errorf("deploy: decrypt registry password: %w", derr)
		}
		regPassword = pw
	}

	// 3) Собираем параметры деплоя и валидируем их пакетным методом.
	params := remotedeploy.DeployParams{
		RegistryHost:      normalizeRegistryHost(reg.URL),
		RegistryNamespace: reg.Namespace,
		RegistryUsername:  reg.Username,
		RegistryPassword:  regPassword,
		RegistryInsecure:  reg.Insecure,
		Image:             in.Image,
		Tag:               in.Tag,
		ContainerName:     in.ContainerName,
		RestartPolicy:     in.RestartPolicy,
	}
	for _, p := range in.Ports {
		params.Ports = append(params.Ports, remotedeploy.PortMapping{Host: p.Host, Container: p.Container})
	}
	// Дефолт: если порты не переданы, используем 3000:80. Это удобно для веб-UI
	// — самых частых деплоев. Runner всё равно требует хотя бы одного маппинга
	// (инвариант защиты ниже сервиса), поэтому подставляем здесь, а не там.
	if len(params.Ports) == 0 {
		params.Ports = []remotedeploy.PortMapping{{Host: 3000, Container: 80}}
	}
	if verr := remotedeploy.ValidateParams(params); verr != nil {
		return nil, domain.ValidationErrors{
			&domain.ValidationError{Field: "params", Message: verr.Error()},
		}
	}

	// 4) Открываем SSH-сессию к серверу.
	client, method, failRes, err := s.openRemoteSession(ctx, in.ServerID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		now := s.clock()
		s.logger.Info("server deploy", "server_id", in.ServerID, "status", failRes.Status, "connected", false)
		return &DeployOutput{
			ID:        in.ServerID,
			Connected: false,
			Status:    failRes.Status,
			Message:   failRes.Message,
			CheckedAt: now,
		}, nil
	}
	defer client.Close()

	// 5) Выполняем шаги.
	result := s.deployer.Run(ctx, client, params)

	now := s.clock()

	// Записываем last_status: успешный деплой = OK, иначе ERROR (с описанием).
	statusForDB := sshclient.StatusOK
	errMsgForDB := ""
	if !result.Success {
		statusForDB = sshclient.StatusError
		errMsgForDB = "deploy failed: " + firstFailedStep(result)
	}
	if uerr := s.repo.UpdateConnectionStatus(ctx, in.ServerID, statusForDB, errMsgForDB, now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", in.ServerID)
	}

	s.logger.Info("server deploy",
		"server_id", in.ServerID,
		"registry_id", in.RegistryID,
		"image_ref", result.ImageRef,
		"container_name", result.ContainerName,
		"success", result.Success,
		"duration_ms", result.DurationMS,
	)

	msg := "deploy succeeded: " + result.ImageRef
	if !result.Success {
		msg = "deploy failed: " + firstFailedStep(result)
	}
	return &DeployOutput{
		ID:        in.ServerID,
		Connected: true,
		Method:    method,
		Status:    statusForDB,
		Message:   msg,
		CheckedAt: now,
		Result:    result,
	}, nil
}

// normalizeRegistryHost вырезает схему (http/https) и trailing slash из URL
// записи registry. Это нужно, потому что в БД URL может быть как
// "https://registry-1.docker.io", так и просто "docker.io" — оба варианта
// валидны, но docker CLI ожидает host без схемы.
func normalizeRegistryHost(url string) string {
	url = strings.TrimSpace(url)
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimSuffix(url, "/")
	if url == "" {
		return "docker.io"
	}
	// Если в URL внезапно есть путь — отрезаем (registry-логин принимает только host[:port]).
	if i := strings.Index(url, "/"); i >= 0 {
		url = url[:i]
	}
	return url
}

// firstFailedStep — короткое описание первого упавшего шага для UI/логов.
func firstFailedStep(r *remotedeploy.DeployResult) string {
	if r == nil {
		return "unknown error"
	}
	for _, s := range r.Steps {
		if s.Status == remotedeploy.StatusFailed {
			return s.Name + ": " + s.Message
		}
	}
	if !r.Available {
		return r.Reason
	}
	return "unknown error"
}

// RemoteServices возвращает список systemd-сервисов с удалённого сервера через
// SSH + CLI `systemctl`. JSON-форма ответа эквивалентна /api/system/services.
// is_active не трогаем — метод диагностический.
func (s *ServerService) RemoteServices(ctx context.Context, id uuid.UUID) (*RemoteServicesOutput, error) {
	if s.servicesRemote == nil {
		return nil, fmt.Errorf("server: remote services collector is not configured")
	}
	client, method, failRes, err := s.openRemoteSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if client == nil {
		now := s.clock()
		s.logger.Info("server remote services", "server_id", id, "status", failRes.Status, "connected", false)
		return &RemoteServicesOutput{
			ID: id, Connected: false, Status: failRes.Status, Message: failRes.Message, CheckedAt: now,
		}, nil
	}
	defer client.Close()

	info := s.servicesRemote.Collect(ctx, client)

	now := s.clock()
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, sshclient.StatusOK, "", now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}
	s.logger.Info("server remote services",
		"server_id", id, "status", sshclient.StatusOK, "method", method, "connected", true,
		"count", info.Count, "available", info.Available,
	)
	return &RemoteServicesOutput{
		ID:        id,
		Connected: true,
		Method:    method,
		Status:    sshclient.StatusOK,
		Message:   "services collected via " + method,
		CheckedAt: now,
		Services:  info,
	}, nil
}

// openRemoteSession — общий хелпер для методов, которым нужно живое SSH-соединение
// к серверу (RemoteContainers, RemoteServices, RemoteSystemInfo). При проблемах
// коннекта возвращает (nil, "", failRes, nil) — caller должен сам обернуть в Output
// со status/message и НЕ пытаться открывать сессии.
//
// На уровне ошибок: метод возвращает ошибку только при проблемах нашей стороны
// (нет сервера в БД, шифрование/конфиг). Сетевые/auth — это failRes.
func (s *ServerService) openRemoteSession(ctx context.Context, id uuid.UUID) (*ssh.Client, string, sshclient.Result, error) {
	srv, password, err := s.loadServerForSSH(ctx, id)
	if err != nil {
		return nil, "", sshclient.Result{}, err
	}
	client, method, failRes := s.connector.Dial(ctx, sshclient.Target{
		Host:     srv.Host,
		Port:     srv.Port,
		User:     srv.Username,
		Password: password,
	})
	if client == nil {
		// Сетевые проблемы / auth fail — фиксируем как у /remote/connect.
		now := s.clock()
		if uerr := s.repo.UpdateConnectionStatus(ctx, id, failRes.Status, failRes.Message, now, nil); uerr != nil {
			s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
		}
		return nil, "", failRes, nil
	}
	return client, method, failRes, nil
}

// InstallSSHKey устанавливает наш SSH-ключ приложения в authorized_keys
// удалённого сервера. Заходит ПО ПАРОЛЮ (ключа на сервере ещё нет), добавляет
// публичный ключ идемпотентно, проверяет верификацией (повторным коннектом по
// ключу), и при успехе ставит ssh_key_installed=true в БД.
//
// Недоступность сервера / неверный пароль — НЕ ошибка метода: 200 с подробным
// статусом в теле. Ошибки метода — только проблемы запроса/конфигурации.
func (s *ServerService) InstallSSHKey(ctx context.Context, id uuid.UUID) (*InstallSSHKeyOutput, error) {
	srv, password, err := s.loadServerForSSH(ctx, id)
	if err != nil {
		return nil, err // ValidationErrors / domain.ErrNotFound / decrypt error
	}

	// Без пароля установка ключа невозможна — это бутстрап, ключа на сервере ещё нет.
	if password == "" {
		return nil, domain.ValidationErrors{
			&domain.ValidationError{Field: "password", Message: "server has no password — install-key requires password to bootstrap"},
		}
	}

	// Берём наш публичный ключ.
	keyInfo, err := s.keys.Check(ctx)
	if err != nil {
		return nil, fmt.Errorf("install-key: read app ssh key: %w", err)
	}
	if !keyInfo.Valid || keyInfo.PublicKey == "" {
		return nil, domain.ValidationErrors{
			&domain.ValidationError{Field: "ssh_key", Message: "app ssh key is missing or invalid — create it via POST /api/system/ssh/create"},
		}
	}

	res := s.connector.InstallPublicKey(ctx, sshclient.Target{
		Host:     srv.Host,
		Port:     srv.Port,
		User:     srv.Username,
		Password: password,
	}, keyInfo.PublicKey)

	now := s.clock()

	// Ставим флаг в БД ТОЛЬКО при подтверждённой работе ключа.
	flagSet := false
	if res.Verified {
		if err := s.repo.MarkSSHKeyInstalled(ctx, id, true); err != nil {
			s.logger.Warn("mark ssh_key_installed", "err", err, "server_id", id)
		} else {
			flagSet = true
		}
	}

	// Полезно также обновить last_status: успех install-key — это и успешный коннект.
	errMsg := ""
	if !res.Connected {
		errMsg = res.Message
	}
	if uerr := s.repo.UpdateConnectionStatus(ctx, id, res.Status, errMsg, now, nil); uerr != nil {
		s.logger.Warn("update server connection status", "err", uerr, "server_id", id)
	}

	s.logger.Info("server install ssh key",
		"server_id", id,
		"status", res.Status,
		"already_installed", res.AlreadyInstalled,
		"installed", res.Installed,
		"verified", res.Verified,
	)

	return &InstallSSHKeyOutput{
		ID:               id,
		Connected:        res.Connected,
		AlreadyInstalled: res.AlreadyInstalled,
		Installed:        res.Installed,
		Verified:         res.Verified,
		SSHKeyInstalled:  flagSet,
		Status:           res.Status,
		Message:          res.Message,
		CheckedAt:        now,
	}, nil
}

// loadServerForSSH достаёт сервер по id и расшифровывает пароль.
func (s *ServerService) loadServerForSSH(ctx context.Context, id uuid.UUID) (*domain.Server, string, error) {
	if id == uuid.Nil {
		return nil, "", domain.ValidationErrors{
			&domain.ValidationError{Field: "id", Message: "is required"},
		}
	}
	srv, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, "", err // в т.ч. domain.ErrNotFound
	}
	password := ""
	if srv.PasswordEncrypted != "" {
		pw, derr := s.cipher.Decrypt(srv.PasswordEncrypted)
		if derr != nil {
			return nil, "", fmt.Errorf("server: decrypt password: %w", derr)
		}
		password = pw
	}
	return srv, password, nil
}

// CreateServer нормализует вход, валидирует, шифрует секреты и сохраняет сервер.
func (s *ServerService) CreateServer(ctx context.Context, input CreateServerInput) (*ServerView, error) {
	in := normalizeCreateServerInput(input)
	if errs := validateServerFields(in.Name, in.Host, in.Port, in.Protocol, in.Username, in.AuthMethod, in.Environment, in.Provider, in.Location, in.Tags); len(errs) > 0 {
		return nil, errs
	}

	pwEnc, err := s.encryptOptional(in.Password)
	if err != nil {
		return nil, err
	}
	keyEnc, err := s.encryptOptional(in.PrivateKey)
	if err != nil {
		return nil, err
	}
	passEnc, err := s.encryptOptional(in.PrivateKeyPassphrase)
	if err != nil {
		return nil, err
	}

	now := s.clock()
	srv := &domain.Server{
		ID:                            uuid.New(),
		Name:                          in.Name,
		Host:                          in.Host,
		Port:                          in.Port,
		Protocol:                      in.Protocol,
		Username:                      in.Username,
		AuthMethod:                    in.AuthMethod,
		PasswordEncrypted:             pwEnc,
		PrivateKeyEncrypted:           keyEnc,
		PrivateKeyPassphraseEncrypted: passEnc,
		Description:                   in.Description,
		Environment:                  in.Environment,
		Provider:                     in.Provider,
		Location:                     in.Location,
		Tags:                         in.Tags,
		IsActive:                     true, // сервер включён при создании
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}

	if err := s.repo.Create(ctx, srv); err != nil {
		return nil, err // в т.ч. domain.ErrAlreadyExists
	}

	s.logger.Info("server created", "server_id", srv.ID, "name", srv.Name, "host", srv.Host)
	return toServerView(srv), nil
}

// UpdateServer полностью обновляет сервер. Секреты обновляются только если заданы.
func (s *ServerService) UpdateServer(ctx context.Context, input UpdateServerInput) (*ServerView, error) {
	in := normalizeUpdateServerInput(input)

	var errs domain.ValidationErrors
	if in.ID == uuid.Nil {
		errs = append(errs, &domain.ValidationError{Field: "id", Message: "is required"})
	}
	errs = append(errs, validateServerFields(in.Name, in.Host, in.Port, in.Protocol, in.Username, in.AuthMethod, in.Environment, in.Provider, in.Location, in.Tags)...)
	if len(errs) > 0 {
		return nil, errs
	}

	existing, err := s.repo.GetByID(ctx, in.ID)
	if err != nil {
		return nil, err // в т.ч. domain.ErrNotFound
	}

	pwEnc, err := s.resolveSecret(in.Password, existing.PasswordEncrypted)
	if err != nil {
		return nil, err
	}
	keyEnc, err := s.resolveSecret(in.PrivateKey, existing.PrivateKeyEncrypted)
	if err != nil {
		return nil, err
	}
	passEnc, err := s.resolveSecret(in.PrivateKeyPassphrase, existing.PrivateKeyPassphraseEncrypted)
	if err != nil {
		return nil, err
	}

	srv := &domain.Server{
		ID:                            in.ID,
		Name:                          in.Name,
		Host:                          in.Host,
		Port:                          in.Port,
		Protocol:                      in.Protocol,
		Username:                      in.Username,
		AuthMethod:                    in.AuthMethod,
		PasswordEncrypted:             pwEnc,
		PrivateKeyEncrypted:           keyEnc,
		PrivateKeyPassphraseEncrypted: passEnc,
		Description:                   in.Description,
		Environment:                  in.Environment,
		Provider:                     in.Provider,
		Location:                     in.Location,
		Tags:                         in.Tags,
		IsActive:                     in.IsActive,
		// факты (OS/CPU/...) через CRUD не меняются — заполняются при подключении.
	}

	if err := s.repo.Update(ctx, srv); err != nil {
		return nil, err // ErrNotFound / ErrAlreadyExists
	}

	s.logger.Info("server updated", "server_id", srv.ID, "name", srv.Name)
	return toServerView(srv), nil
}

// ListServers возвращает страницу серверов с фильтрами.
func (s *ServerService) ListServers(ctx context.Context, in ListServersInput) (*ListServersOutput, error) {
	var errs domain.ValidationErrors
	env := strings.ToUpper(strings.TrimSpace(in.Environment))
	if env != "" && !domain.IsValidServerEnvironment(env) {
		errs = append(errs, &domain.ValidationError{Field: "environment", Message: "invalid value"})
	}
	proto := strings.ToUpper(strings.TrimSpace(in.Protocol))
	if proto != "" && !domain.IsValidServerProtocol(proto) {
		errs = append(errs, &domain.ValidationError{Field: "protocol", Message: "invalid value"})
	}
	auth := strings.ToUpper(strings.TrimSpace(in.AuthMethod))
	if auth != "" && !domain.IsValidServerAuthMethod(auth) {
		errs = append(errs, &domain.ValidationError{Field: "auth_method", Message: "invalid value"})
	}
	if len(errs) > 0 {
		return nil, errs
	}

	page := in.Page
	if page < 1 {
		page = 1
	}
	size := in.PageSize
	if size < 1 {
		size = defaultServerPageSize
	}
	if size > maxServerPageSize {
		size = maxServerPageSize
	}

	filter := domain.ServerListFilter{
		Environment: env,
		Protocol:    proto,
		AuthMethod:  auth,
		IsActive:    in.IsActive,
		Search:      strings.TrimSpace(in.Search),
		Limit:       size,
		Offset:      (page - 1) * size,
		SortBy:      in.SortBy,
		SortDesc:    strings.ToLower(in.Order) != "asc",
	}

	items, total, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	totalPages := 0
	if total > 0 {
		totalPages = (total + size - 1) / size
	}

	out := &ListServersOutput{
		Items: make([]ServerView, 0, len(items)),
		Pagination: Pagination{
			Page:       page,
			PageSize:   size,
			Total:      total,
			TotalPages: totalPages,
		},
	}
	for _, srv := range items {
		out.Items = append(out.Items, *toServerView(srv))
	}
	return out, nil
}

// DeleteServer мягко удаляет сервер по ID.
func (s *ServerService) DeleteServer(ctx context.Context, id uuid.UUID) (*DeleteServerOutput, error) {
	if id == uuid.Nil {
		return nil, domain.ValidationErrors{
			&domain.ValidationError{Field: "id", Message: "is required"},
		}
	}
	deletedAt, err := s.repo.SoftDelete(ctx, id)
	if err != nil {
		return nil, err // в т.ч. domain.ErrNotFound
	}
	s.logger.Info("server deleted", "server_id", id)
	return &DeleteServerOutput{ID: id, DeletedAt: deletedAt}, nil
}

// ───────────────────────────── helpers ─────────────────────────────

func (s *ServerService) encryptOptional(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	ct, err := s.cipher.Encrypt(plain)
	if err != nil {
		return "", fmt.Errorf("server: encrypt secret: %w", err)
	}
	return ct, nil
}

// resolveSecret: nil → оставить existing; "" → очистить; значение → зашифровать.
func (s *ServerService) resolveSecret(input *string, existing string) (string, error) {
	if input == nil {
		return existing, nil
	}
	if *input == "" {
		return "", nil
	}
	return s.encryptOptional(*input)
}

func toServerView(s *domain.Server) *ServerView {
	return &ServerView{
		ID:               s.ID,
		Name:             s.Name,
		Host:             s.Host,
		Port:             s.Port,
		Protocol:         s.Protocol,
		Username:         s.Username,
		AuthMethod:       s.AuthMethod,
		Description:      s.Description,
		Environment:      s.Environment,
		Provider:         s.Provider,
		Location:         s.Location,
		Tags:             s.Tags,
		OS:               s.OS,
		OSVersion:        s.OSVersion,
		Arch:             s.Arch,
		KernelVersion:    s.KernelVersion,
		RemoteHostname:   s.RemoteHostname,
		CPUCores:         s.CPUCores,
		MemoryTotalBytes: s.MemoryTotalBytes,
		DiskTotalBytes:   s.DiskTotalBytes,
		RemotePublicIP:   s.RemotePublicIP,
		CountryCode:      s.CountryCode,
		Country:          s.Country,
		HasPassword:      s.PasswordEncrypted != "",
		HasPrivateKey:    s.PrivateKeyEncrypted != "",
		IsActive:         s.IsActive,
		SSHKeyInstalled:  s.SSHKeyInstalled,
		LastCheckedAt:    s.LastCheckedAt,
		LastStatus:       s.LastStatus,
		CreatedAt:        s.CreatedAt,
		UpdatedAt:        s.UpdatedAt,
	}
}

func normalizeCreateServerInput(in CreateServerInput) CreateServerInput {
	out := CreateServerInput{
		Name:                 strings.TrimSpace(in.Name),
		Host:                 strings.TrimSpace(in.Host),
		Port:                 in.Port,
		Protocol:             strings.ToUpper(strings.TrimSpace(in.Protocol)),
		Username:             strings.TrimSpace(in.Username),
		AuthMethod:           strings.ToUpper(strings.TrimSpace(in.AuthMethod)),
		Password:             in.Password,
		PrivateKey:           in.PrivateKey,
		PrivateKeyPassphrase: in.PrivateKeyPassphrase,
		Description:          strings.TrimSpace(in.Description),
		Environment:          strings.ToUpper(strings.TrimSpace(in.Environment)),
		Provider:             strings.TrimSpace(in.Provider),
		Location:             strings.TrimSpace(in.Location),
		Tags:                 normalizeTags(in.Tags),
	}
	applyServerDefaults(&out.Port, &out.Protocol, &out.AuthMethod, &out.Environment)
	return out
}

func normalizeUpdateServerInput(in UpdateServerInput) UpdateServerInput {
	out := UpdateServerInput{
		ID:                   in.ID,
		Name:                 strings.TrimSpace(in.Name),
		Host:                 strings.TrimSpace(in.Host),
		Port:                 in.Port,
		Protocol:             strings.ToUpper(strings.TrimSpace(in.Protocol)),
		Username:             strings.TrimSpace(in.Username),
		AuthMethod:           strings.ToUpper(strings.TrimSpace(in.AuthMethod)),
		Password:             in.Password,
		PrivateKey:           in.PrivateKey,
		PrivateKeyPassphrase: in.PrivateKeyPassphrase,
		Description:          strings.TrimSpace(in.Description),
		Environment:          strings.ToUpper(strings.TrimSpace(in.Environment)),
		Provider:             strings.TrimSpace(in.Provider),
		Location:             strings.TrimSpace(in.Location),
		Tags:                 normalizeTags(in.Tags),
		IsActive:             in.IsActive,
	}
	applyServerDefaults(&out.Port, &out.Protocol, &out.AuthMethod, &out.Environment)
	return out
}

// applyServerDefaults проставляет дефолты для незаданных полей.
func applyServerDefaults(port *int, protocol, authMethod, environment *string) {
	if *port == 0 {
		*port = defaultSSHPort
	}
	if *protocol == "" {
		*protocol = domain.ServerProtocolSSH
	}
	if *authMethod == "" {
		*authMethod = domain.ServerAuthPassword
	}
	if *environment == "" {
		*environment = domain.ServerEnvProduction
	}
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func validateServerFields(name, host string, port int, protocol, username, authMethod, environment, provider, location string, tags []string) domain.ValidationErrors {
	var errs domain.ValidationErrors

	switch {
	case name == "":
		errs = append(errs, &domain.ValidationError{Field: "name", Message: "is required"})
	default:
		if l := utf8.RuneCountInString(name); l < 2 || l > 100 {
			errs = append(errs, &domain.ValidationError{Field: "name", Message: "must be between 2 and 100 characters"})
		}
	}

	switch {
	case host == "":
		errs = append(errs, &domain.ValidationError{Field: "host", Message: "is required"})
	default:
		if utf8.RuneCountInString(host) > 255 {
			errs = append(errs, &domain.ValidationError{Field: "host", Message: "must be at most 255 characters"})
		}
	}

	if port < 1 || port > 65535 {
		errs = append(errs, &domain.ValidationError{Field: "port", Message: "must be between 1 and 65535"})
	}

	if !domain.IsValidServerProtocol(protocol) {
		errs = append(errs, &domain.ValidationError{Field: "protocol", Message: "must be one of SSH, WINRM, RDP"})
	}
	if !domain.IsValidServerAuthMethod(authMethod) {
		errs = append(errs, &domain.ValidationError{Field: "auth_method", Message: "must be one of PASSWORD, PRIVATE_KEY, AGENT"})
	}
	if !domain.IsValidServerEnvironment(environment) {
		errs = append(errs, &domain.ValidationError{Field: "environment", Message: "must be one of PRODUCTION, STAGING, DEVELOPMENT, TESTING, OTHER"})
	}

	if username != "" && utf8.RuneCountInString(username) > 255 {
		errs = append(errs, &domain.ValidationError{Field: "username", Message: "must be at most 255 characters"})
	}
	if provider != "" && utf8.RuneCountInString(provider) > 100 {
		errs = append(errs, &domain.ValidationError{Field: "provider", Message: "must be at most 100 characters"})
	}
	if location != "" && utf8.RuneCountInString(location) > 100 {
		errs = append(errs, &domain.ValidationError{Field: "location", Message: "must be at most 100 characters"})
	}

	if len(tags) > maxServerTags {
		errs = append(errs, &domain.ValidationError{Field: "tags", Message: fmt.Sprintf("must be at most %d tags", maxServerTags)})
	}
	for _, t := range tags {
		if utf8.RuneCountInString(t) > maxServerTagLen {
			errs = append(errs, &domain.ValidationError{Field: "tags", Message: fmt.Sprintf("each tag must be at most %d characters", maxServerTagLen)})
			break
		}
	}

	return errs
}
