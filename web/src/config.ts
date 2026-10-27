export interface AppConfig {
  region: string;
  userPoolId: string;
  clientId: string;
  authDomain: string;
  redirectUri: string;
  logoutUri: string;
  apiBase: '/api';
}

export function validateConfig(value: unknown, origin: string): AppConfig {
  if (!value || typeof value !== 'object') throw new Error('Invalid application configuration.');
  const v = value as Record<string, unknown>;
  for (const key of ['region', 'userPoolId', 'clientId', 'authDomain', 'redirectUri', 'logoutUri']) {
    if (typeof v[key] !== 'string' || !v[key]) throw new Error('Incomplete application configuration.');
  }
  if (!/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(v.region as string)
    || !new RegExp(`^${v.region}_[a-zA-Z0-9]+$`).test(v.userPoolId as string)
    || !/^[a-zA-Z0-9]+$/.test(v.clientId as string)
    || v.apiBase !== '/api') throw new Error('Invalid application configuration.');
  const auth = new URL(v.authDomain as string);
  if (auth.protocol !== 'https:' || auth.username || auth.password || auth.pathname !== '/'
    || auth.search || auth.hash) throw new Error('Invalid authentication origin.');
  for (const key of ['redirectUri', 'logoutUri']) {
    const url = new URL(v[key] as string);
    if (url.origin !== origin || url.username || url.password || url.hash || url.search) {
      throw new Error('Authentication redirects must use this application origin.');
    }
  }
  return v as unknown as AppConfig;
}

export async function loadConfig(): Promise<AppConfig> {
  const response = await fetch('/app-config.json', {
    cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error('Application configuration is unavailable.');
  return validateConfig(await response.json(), window.location.origin);
}
