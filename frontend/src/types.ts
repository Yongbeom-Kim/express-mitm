export type ProxyConfig = {
  enabled: boolean;
  host: string;
  port: number;
  authenticated: boolean;
  bypassAllowed: boolean;
};

export type ServiceStatus = {
  http: ProxyConfig;
  https: ProxyConfig;
};

export type AppStatus = {
  enabled: boolean;
  running: boolean;
  proxyHost: string;
  proxyPort: number;
  proxyAddr: string;
  service: string;
  services: string[];
  certPath: string;
  certExists: boolean;
  proxyControllerAvailable: boolean;
  proxyControllerError?: string;
  systemProxy: ServiceStatus;
  systemProxyManaged: boolean;
  lastError?: string;
};
