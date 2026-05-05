package proxyctl

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func listDarwinServices(ctx context.Context) ([]string, error) {
	output, err := runNetworksetup(ctx, "-listallnetworkservices")
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

func setDarwinProxy(ctx context.Context, service, host string, port int) error {
	portString := strconv.Itoa(port)
	commands := [][]string{
		{"-setwebproxy", service, host, portString},
		{"-setsecurewebproxy", service, host, portString},
		{"-setwebproxystate", service, "on"},
		{"-setsecurewebproxystate", service, "on"},
	}

	for _, args := range commands {
		if _, err := runNetworksetup(ctx, args...); err != nil {
			return err
		}
	}

	return nil
}

func unsetDarwinProxy(ctx context.Context, service string) error {
	commands := [][]string{
		{"-setwebproxystate", service, "off"},
		{"-setsecurewebproxystate", service, "off"},
	}

	for _, args := range commands {
		if _, err := runNetworksetup(ctx, args...); err != nil {
			return err
		}
	}

	return nil
}

func darwinStatus(ctx context.Context, service string) (ServiceStatus, error) {
	httpOutput, err := runNetworksetup(ctx, "-getwebproxy", service)
	if err != nil {
		return ServiceStatus{}, err
	}

	httpsOutput, err := runNetworksetup(ctx, "-getsecurewebproxy", service)
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

func runNetworksetup(ctx context.Context, args ...string) (string, error) {
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
