import type {AppStatus} from '../types';

type BackendApp = {
  GetStatus(service: string): Promise<AppStatus>;
  SetProxyEnabled(enabled: boolean): Promise<void>;
};

declare global {
  interface Window {
    go?: {
      main?: {
        App?: BackendApp;
      };
    };
  }
}

function backend(): BackendApp {
  const app = window.go?.main?.App;
  if (!app) {
    throw new Error('Wails runtime is unavailable. Run this project with `wails dev` or use a packaged build.');
  }
  return app;
}

export function getStatus(service = ''): Promise<AppStatus> {
  return backend().GetStatus(service);
}

export function setProxyEnabled(enabled: boolean): Promise<void> {
  return backend().SetProxyEnabled(enabled);
}
