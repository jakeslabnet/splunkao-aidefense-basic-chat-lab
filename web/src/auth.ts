import { UserManager, WebStorageStateStore } from 'oidc-client-ts';
import type { AppConfig } from './config';

export function createAuth(config: AppConfig): UserManager {
  return new UserManager({
    authority: `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`,
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    post_logout_redirect_uri: config.logoutUri,
    response_type: 'code',
    scope: 'openid email agent-chat/invoke',
    automaticSilentRenew: false,
    loadUserInfo: false,
    staleStateAgeInSeconds: 300,
    requestTimeoutInSeconds: 15,
    // The library supplies cryptographically random state and S256 PKCE. Tokens and
    // transient redirect state expire with this browser tab; chat is never stored.
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    revokeTokenTypes: ['refresh_token'],
    metadata: {
      issuer: `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`,
      authorization_endpoint: `${config.authDomain}/oauth2/authorize`,
      token_endpoint: `${config.authDomain}/oauth2/token`,
      revocation_endpoint: `${config.authDomain}/oauth2/revoke`,
      jwks_uri: `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}/.well-known/jwks.json`,
    },
  });
}

export async function signOut(auth: UserManager, config: AppConfig): Promise<void> {
  try { await auth.revokeTokens(['refresh_token']); } catch { /* Local logout still proceeds. */ }
  await auth.removeUser();
  const url = new URL('/logout', config.authDomain);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('logout_uri', config.logoutUri);
  window.location.assign(url.toString());
}
