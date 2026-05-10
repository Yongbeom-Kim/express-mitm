import {useEffect, useState} from 'react';
import './App.css';
import {getStatus, setProxyEnabled} from './lib/backend';
import type {AppStatus} from './types';

const emptyStatus: AppStatus = {
  enabled: false,
  running: false,
  proxyHost: '127.0.0.1',
  proxyPort: 16326,
  proxyAddr: '127.0.0.1:16326',
  service: '',
  services: [],
  certPath: '~/.express-mitm/cert/ca.crt',
  certExists: false,
  proxyControllerAvailable: false,
  proxyControllerError: '',
  systemProxy: {
    http: {
      enabled: false,
      host: '',
      port: 0,
      authenticated: false,
      bypassAllowed: false,
    },
    https: {
      enabled: false,
      host: '',
      port: 0,
      authenticated: false,
      bypassAllowed: false,
    },
  },
  systemProxyManaged: false,
  lastError: '',
};

function App() {
  const [status, setStatus] = useState<AppStatus>(emptyStatus);
  const [busyTarget, setBusyTarget] = useState<boolean | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    void refreshStatus();
  }, []);

  useEffect(() => {
    if (!status.enabled && !status.running) {
      return;
    }

    const intervalId = window.setInterval(() => {
      void refreshStatus().catch(() => undefined);
    }, 4000);

    return () => window.clearInterval(intervalId);
  }, [status.enabled, status.running]);

  async function refreshStatus() {
    const nextStatus = await getStatus('');
    setStatus(nextStatus);
    setError('');
  }

  async function handleToggle(nextEnabled: boolean) {
    setBusyTarget(nextEnabled);
    setError('');

    try {
      await setProxyEnabled(nextEnabled);
      await refreshStatus();
    } catch (err) {
      setError(messageOf(err));
      await refreshStatus().catch(() => undefined);
    } finally {
      setBusyTarget(null);
    }
  }

  const busy = busyTarget !== null;
  const active = status.enabled;
  const serviceLabel = status.service || 'Auto';
  const subtitle = active
    ? `Traffic is routed through ${status.proxyAddr}.`
    : `Traffic is going directly out. Listener stays at ${status.proxyAddr}.`;
  const helper = status.proxyControllerAvailable
    ? `Turning this on starts the local Go proxy and enables the macOS system proxy for ${serviceLabel}.`
    : 'Turning this on starts the local Go proxy server only.';

  return (
    <div className="app-shell">
      <main className="panel">
        <p className="eyebrow">express-mitm</p>
        <h1>Proxy</h1>
        <p className="subtitle">{subtitle}</p>

        <label className={`toggle ${active ? 'on' : 'off'} ${busy ? 'busy' : ''}`}>
          <input
            type="checkbox"
            checked={active}
            disabled={busy}
            onChange={(event) => handleToggle(event.target.checked)}
          />
          <span className="track" aria-hidden="true">
            <span className="thumb" />
          </span>
          <span className="copy">
            <strong>
              {busy
                ? busyTarget
                  ? 'Turning on...'
                  : 'Turning off...'
                : active
                  ? 'On'
                  : 'Off'}
            </strong>
            <span>{active ? 'Intercepting traffic now.' : 'Proxy is idle.'}</span>
          </span>
        </label>

        {(error || status.lastError || status.proxyControllerError) && (
          <div className="alert error">{error || status.lastError || status.proxyControllerError}</div>
        )}

        <div className="facts">
          <div className="fact">
            <span>Listener</span>
            <strong>{status.proxyAddr}</strong>
          </div>
          <div className="fact">
            <span>Network service</span>
            <strong>{serviceLabel}</strong>
          </div>
          <div className="fact">
            <span>Certificate</span>
            <strong>{status.certExists ? 'Ready' : 'Generated on first enable'}</strong>
          </div>
        </div>

        <p className="helper">{helper}</p>
      </main>
    </div>
  );
}

function messageOf(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export default App;
