package proxyctl

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type macOSController struct{}

func (controller *macOSController) SetProxy(ctx context.Context, service, host string, port int) error {
	if service == "" {
		return errors.New("proxyctl: service is required")
	}
	if host == "" {
		return errors.New("proxyctl: host is required")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("proxyctl: invalid port %d", port)
	}

	portString := strconv.Itoa(port)
	commands := [][]string{
		{"-setwebproxy", service, host, portString},
		{"-setsecurewebproxy", service, host, portString},
		{"-setwebproxystate", service, "on"},
		{"-setsecurewebproxystate", service, "on"},
	}

	for _, args := range commands {
		if _, err := controller.runNetworksetup(ctx, args...); err != nil {
			return err
		}
	}

	return nil
}

func (controller *macOSController) UnsetProxy(ctx context.Context, service string) error {
	if service == "" {
		return errors.New("proxyctl: service is required")
	}

	commands := [][]string{
		{"-setwebproxystate", service, "off"},
		{"-setsecurewebproxystate", service, "off"},
	}

	for _, args := range commands {
		if _, err := controller.runNetworksetup(ctx, args...); err != nil {
			return err
		}
	}

	return nil
}

func (controller *macOSController) ListProxies(ctx context.Context, service string) (ServiceStatus, error) {
	if service == "" {
		return ServiceStatus{}, errors.New("proxyctl: service is required")
	}

	httpOutput, err := controller.runNetworksetup(ctx, "-getwebproxy", service)
	if err != nil {
		return ServiceStatus{}, err
	}

	httpsOutput, err := controller.runNetworksetup(ctx, "-getsecurewebproxy", service)
	if err != nil {
		return ServiceStatus{}, err
	}

	httpConfig, err := parseDarwinProxyConfig(httpOutput)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("proxyctl: parse HTTP proxy status: %w", err)
	}

	httpsConfig, err := parseDarwinProxyConfig(httpsOutput)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("proxyctl: parse HTTPS proxy status: %w", err)
	}

	return ServiceStatus{
		HTTP:  httpConfig,
		HTTPS: httpsConfig,
	}, nil
}

func (controller *macOSController) ListServices(ctx context.Context) ([]string, error) {
	output, err := controller.runNetworksetup(ctx, "-listallnetworkservices")
	if err != nil {
		return nil, err
	}

	var services []string
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}

		services = append(services, strings.TrimPrefix(line, "* "))
	}

	return services, nil
}

func (*macOSController) runNetworksetup(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "networksetup", args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), nil
	}

	detail := strings.TrimSpace(string(output))
	if detail == "" {
		return "", fmt.Errorf("proxyctl: networksetup %s: %w", formatCommandArgs(args), err)
	}

	return "", fmt.Errorf("proxyctl: networksetup %s: %w: %s", formatCommandArgs(args), err, detail)
}

func parseDarwinProxyConfig(output string) (ProxyConfig, error) {
	config := ProxyConfig{}

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "Enabled":
			enabled, err := parseDarwinBool(value)
			if err != nil {
				return ProxyConfig{}, fmt.Errorf("enabled: %w", err)
			}
			config.Enabled = enabled
		case "Server":
			config.Host = value
		case "Port":
			if value == "" {
				continue
			}

			port, err := strconv.Atoi(value)
			if err != nil {
				return ProxyConfig{}, fmt.Errorf("port: %w", err)
			}
			config.Port = port
		case "Authenticated Proxy Enabled":
			authenticated, err := parseDarwinBool(value)
			if err != nil {
				return ProxyConfig{}, fmt.Errorf("authenticated proxy enabled: %w", err)
			}
			config.Authenticated = authenticated
		case "Bypass Allowed":
			bypassAllowed, err := parseDarwinBool(value)
			if err != nil {
				return ProxyConfig{}, fmt.Errorf("bypass allowed: %w", err)
			}
			config.BypassAllowed = bypassAllowed
		}
	}

	return config, nil
}

func parseDarwinBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "on", "1", "true":
		return true, nil
	case "no", "off", "0", "false":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected boolean value %q", value)
	}
}

func formatCommandArgs(args []string) string {
	formatted := make([]string, len(args))
	for i, arg := range args {
		formatted[i] = strconv.Quote(arg)
	}

	return strings.Join(formatted, " ")
}
