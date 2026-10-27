# AgentCore Chat web client

Run `npm ci`, `npm test`, and `npm run build`. Publish `dist/` to the private CloudFront origin, then publish `/app-config.json`:

```json
{
  "region": "us-east-1",
  "userPoolId": "us-east-1_POOL_ID",
  "clientId": "COGNITO_PUBLIC_CLIENT_ID",
  "authDomain": "https://DOMAIN.auth.us-east-1.amazoncognito.com",
  "redirectUri": "https://DISTRIBUTION.cloudfront.net/",
  "logoutUri": "https://DISTRIBUTION.cloudfront.net/",
  "apiBase": "/api"
}
```

This public configuration contains no credentials. Set CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://cognito-idp.us-east-1.amazonaws.com https://DOMAIN.auth.us-east-1.amazoncognito.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'` on CloudFront, plus HSTS and `X-Content-Type-Options: nosniff`. Disable caching for API paths and this configuration file. Callback and sign-out URLs must exactly match Cognito registration and the current application origin.

Authentication uses `oidc-client-ts`, authorization code with S256 PKCE and state validation. The browser client has no secret. Tokens and short-lived flow state use sessionStorage; chat history uses React memory only. There is no localStorage, analytics, external font, raw HTML rendering, file upload, or automatic chat retry. The API receives an access token with `agent-chat/invoke` scope and remains responsible for validating issuer, expiry, client ID, scope, payload, and user isolation.

Stopping or losing a response marks it incomplete. That reply and its paired user turn remain visible but are excluded from later model context. Each request carries at most 19 completed turns plus the current user message; oldest turns are pruned to stay within 64 KiB. Chat continues across runtime expiration because the browser supplies bounded history.

The sidebar starts with neutral “Not verified” integration status. Each completed stream’s `done` event updates `ciscoStatus` (`unconfigured`, `ok`, `findings`, `error`) and `splunkStatus` (`unconfigured`, `accepted`, `error`, `unconfirmed`). Missing or unknown values stay unverified. Splunk “Export accepted” describes SDK export acceptance; dashboard delivery remains explicitly unverified. A new chat resets the indicators. When credentials are configured, prompts and replies are intentionally sent to those services for the demo.
