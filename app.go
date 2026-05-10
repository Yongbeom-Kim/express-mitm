package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Yongbeom-Kim/express-mitm/internal/fs"
	"github.com/Yongbeom-Kim/express-mitm/internal/mitmserver"
	cacert "github.com/Yongbeom-Kim/express-mitm/internal/mitmserver/ca-cert"
	"github.com/Yongbeom-Kim/express-mitm/internal/proxyctl"
)

const proxyctlTimeout = 5 * time.Second

type App struct {
	ctx context.Context

	mu sync.Mutex

	host    string
	port    int
	service string

	server *mitmserver.MitmServer

	controller    proxyctl.Controller
	controllerErr error

	systemProxyManaged bool
	lastError          string
}

type AppStatus struct {
	Enabled                  bool                   `json:"enabled"`
	Running                  bool                   `json:"running"`
	ProxyHost                string                 `json:"proxyHost"`
	ProxyPort                int                    `json:"proxyPort"`
	ProxyAddr                string                 `json:"proxyAddr"`
	Service                  string                 `json:"service"`
	Services                 []string               `json:"services"`
	CertPath                 string                 `json:"certPath"`
	CertExists               bool                   `json:"certExists"`
	ProxyControllerAvailable bool                   `json:"proxyControllerAvailable"`
	ProxyControllerError     string                 `json:"proxyControllerError,omitempty"`
	SystemProxy              proxyctl.ServiceStatus `json:"systemProxy"`
	SystemProxyManaged       bool                   `json:"systemProxyManaged"`
	LastError                string                 `json:"lastError,omitempty"`
}

func NewApp() *App {
	controller, err := proxyctl.New()

	return &App{
		host:          proxyctl.DefaultHost,
		port:          proxyctl.DefaultPort,
		service:       proxyctl.DefaultService,
		controller:    controller,
		controllerErr: err,
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(context.Context) {
	_ = a.StopProxy()
}

func (a *App) GetStatus(service string) (AppStatus, error) {
	status := a.baseStatus(service)
	if !status.ProxyControllerAvailable {
		status.Enabled = deriveEnabled(status)
		return status, nil
	}

	controller, err := a.proxyController()
	if err != nil {
		status.ProxyControllerError = err.Error()
		status.Enabled = deriveEnabled(status)
		return status, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyctlTimeout)
	defer cancel()

	resolvedService, services, err := a.resolveService(ctx, service)
	if err != nil {
		a.setLastError(err)
		status.LastError = err.Error()
		status.Enabled = deriveEnabled(status)
		return status, err
	}

	status.Service = resolvedService
	status.Services = services

	if resolvedService == "" {
		status.Enabled = deriveEnabled(status)
		return status, nil
	}

	proxyStatus, err := controller.ListProxies(ctx, resolvedService)
	if err != nil {
		a.setLastError(err)
		status.LastError = err.Error()
		status.Enabled = deriveEnabled(status)
		return status, err
	}

	status.SystemProxy = proxyStatus
	status.Enabled = deriveEnabled(status)
	return status, nil
}

func (a *App) SetProxyEnabled(enabled bool) error {
	if enabled {
		return a.setProxyEnabled()
	}

	return a.setProxyDisabled()
}

func (a *App) EnsureCertificate() (string, error) {
	authority := cacert.New()
	if err := authority.GenerateCaCert(); err != nil {
		a.setLastError(err)
		return "", err
	}

	a.clearLastError()
	return caCertPath(), nil
}

func (a *App) StartProxy(service string, port int) error {
	a.mu.Lock()
	if a.server != nil {
		err := errors.New("proxy server is already running")
		a.mu.Unlock()
		a.setLastError(err)
		return err
	}

	host := a.host
	currentPort := a.port
	currentService := a.service
	a.mu.Unlock()

	resolvedPort, err := normalisePort(port, currentPort)
	if err != nil {
		a.setLastError(err)
		return err
	}

	resolvedService := normaliseService(service, currentService)
	server := mitmserver.NewMitmServer(net.JoinHostPort(host, strconv.Itoa(resolvedPort)))
	if err := server.Start(); err != nil {
		a.setLastError(err)
		return err
	}

	a.mu.Lock()
	if a.server != nil {
		a.mu.Unlock()
		_ = server.Stop()
		err := errors.New("proxy server is already running")
		a.setLastError(err)
		return err
	}

	a.server = server
	a.port = resolvedPort
	a.service = resolvedService
	a.lastError = ""
	a.mu.Unlock()

	go a.watchServer(server)
	return nil
}

func (a *App) StopProxy() error {
	a.mu.Lock()
	server := a.server
	managed := a.systemProxyManaged
	a.mu.Unlock()

	var errs []error

	if managed {
		if err := a.disableSystemProxy(""); err != nil {
			errs = append(errs, err)
		}
	}

	if server != nil {
		if err := server.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	a.mu.Lock()
	if a.server == server {
		a.server = nil
	}
	if len(errs) == 0 {
		a.lastError = ""
	} else {
		a.lastError = errors.Join(errs...).Error()
	}
	a.mu.Unlock()

	return errors.Join(errs...)
}

func (a *App) setProxyEnabled() error {
	wasRunning, controllerAvailable := a.currentState()

	if _, err := a.EnsureCertificate(); err != nil {
		return err
	}

	if !wasRunning {
		if err := a.StartProxy("", 0); err != nil {
			return err
		}
	}

	if !controllerAvailable {
		a.clearLastError()
		return nil
	}

	if err := a.EnableSystemProxy(""); err != nil {
		if !wasRunning {
			_ = a.stopServerOnly()
		}
		return err
	}

	a.clearLastError()
	return nil
}

func (a *App) setProxyDisabled() error {
	_, controllerAvailable := a.currentState()

	var errs []error
	if controllerAvailable {
		if err := a.DisableSystemProxy(""); err != nil {
			errs = append(errs, err)
		}
	}

	if err := a.stopServerOnly(); err != nil {
		errs = append(errs, err)
	}

	result := errors.Join(errs...)
	if result != nil {
		a.setLastError(result)
		return result
	}

	a.clearLastError()
	return nil
}

func (a *App) EnableSystemProxy(service string) error {
	controller, err := a.proxyController()
	if err != nil {
		a.setLastError(err)
		return err
	}

	a.mu.Lock()
	host := a.host
	port := a.port
	running := a.server != nil
	a.mu.Unlock()

	if !running {
		err := errors.New("start the proxy server before enabling the system proxy")
		a.setLastError(err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyctlTimeout)
	defer cancel()

	resolvedService, _, err := a.resolveService(ctx, service)
	if err != nil {
		a.setLastError(err)
		return err
	}

	if resolvedService == "" {
		err := errors.New("no network services found")
		a.setLastError(err)
		return err
	}

	if err := controller.SetProxy(ctx, resolvedService, host, port); err != nil {
		a.setLastError(err)
		return err
	}

	a.mu.Lock()
	a.service = resolvedService
	a.systemProxyManaged = true
	a.lastError = ""
	a.mu.Unlock()

	return nil
}

func (a *App) DisableSystemProxy(service string) error {
	err := a.disableSystemProxy(service)
	if err != nil {
		a.setLastError(err)
		return err
	}

	a.clearLastError()
	return nil
}

func (a *App) disableSystemProxy(service string) error {
	controller, err := a.proxyController()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyctlTimeout)
	defer cancel()

	resolvedService, _, err := a.resolveService(ctx, service)
	if err != nil {
		return err
	}

	if resolvedService == "" {
		return errors.New("no network services found")
	}

	if err := controller.UnsetProxy(ctx, resolvedService); err != nil {
		return err
	}

	a.mu.Lock()
	a.service = resolvedService
	a.systemProxyManaged = false
	a.mu.Unlock()

	return nil
}

func (a *App) watchServer(server *mitmserver.MitmServer) {
	err := server.Wait()

	a.mu.Lock()
	if a.server == server {
		a.server = nil
	}
	if err != nil {
		a.lastError = err.Error()
	}
	a.mu.Unlock()
}

func (a *App) baseStatus(service string) AppStatus {
	a.mu.Lock()
	host := a.host
	port := a.port
	currentService := a.service
	running := a.server != nil
	managed := a.systemProxyManaged
	lastError := a.lastError
	controllerAvailable := a.controller != nil
	controllerErr := a.controllerErr
	a.mu.Unlock()

	status := AppStatus{
		Enabled:                  running && !controllerAvailable,
		Running:                  running,
		ProxyHost:                host,
		ProxyPort:                port,
		ProxyAddr:                net.JoinHostPort(host, strconv.Itoa(port)),
		Service:                  normaliseService(service, currentService),
		CertPath:                 caCertPath(),
		CertExists:               pathExists(caCertPath()),
		ProxyControllerAvailable: controllerAvailable,
		SystemProxyManaged:       managed,
		LastError:                lastError,
	}
	if !controllerAvailable && controllerErr != nil {
		status.ProxyControllerError = controllerErr.Error()
	}

	return status
}

func (a *App) currentState() (running bool, controllerAvailable bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.server != nil, a.controller != nil
}

func (a *App) resolveService(ctx context.Context, service string) (string, []string, error) {
	controller, err := a.proxyController()
	if err != nil {
		return normaliseService(service, proxyctl.DefaultService), nil, err
	}

	a.mu.Lock()
	currentService := a.service
	a.mu.Unlock()

	desired := normaliseService(service, currentService)
	services, err := controller.ListServices(ctx)
	if err != nil {
		return desired, nil, err
	}

	resolved := selectService(desired, services)
	if resolved != "" {
		a.mu.Lock()
		a.service = resolved
		a.mu.Unlock()
	}

	return resolved, services, nil
}

func (a *App) proxyController() (proxyctl.Controller, error) {
	a.mu.Lock()
	controller := a.controller
	controllerErr := a.controllerErr
	a.mu.Unlock()

	if controller != nil {
		return controller, nil
	}
	if controllerErr != nil {
		return nil, controllerErr
	}
	return nil, errors.New("proxy controller is unavailable")
}

func (a *App) setLastError(err error) {
	a.mu.Lock()
	if err == nil {
		a.lastError = ""
	} else {
		a.lastError = err.Error()
	}
	a.mu.Unlock()
}

func (a *App) clearLastError() {
	a.setLastError(nil)
}

func (a *App) stopServerOnly() error {
	a.mu.Lock()
	server := a.server
	a.mu.Unlock()

	if server == nil {
		return nil
	}

	if err := server.Stop(); err != nil {
		return err
	}

	a.mu.Lock()
	if a.server == server {
		a.server = nil
	}
	a.mu.Unlock()

	return nil
}

func normalisePort(port, fallback int) (int, error) {
	if port == 0 {
		port = fallback
	}
	if port == 0 {
		port = proxyctl.DefaultPort
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid proxy port %d", port)
	}
	return port, nil
}

func normaliseService(service, fallback string) string {
	service = strings.TrimSpace(service)
	if service != "" {
		return service
	}
	fallback = strings.TrimSpace(fallback)
	if fallback != "" {
		return fallback
	}
	return proxyctl.DefaultService
}

func selectService(desired string, services []string) string {
	if len(services) == 0 {
		return desired
	}

	for _, service := range services {
		if service == desired {
			return service
		}
	}

	for _, service := range services {
		if service == proxyctl.DefaultService {
			return service
		}
	}

	return services[0]
}

func caCertPath() string {
	return filepath.Join(fs.ApplicationHomeDir(), "cert", "ca.crt")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func deriveEnabled(status AppStatus) bool {
	if !status.Running {
		return false
	}

	if !status.ProxyControllerAvailable {
		return true
	}

	return status.SystemProxy.HTTP.Enabled || status.SystemProxy.HTTPS.Enabled
}
