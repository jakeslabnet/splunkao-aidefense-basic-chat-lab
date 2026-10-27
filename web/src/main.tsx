import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createAuth } from './auth';
import { loadConfig } from './config';
import './styles.css';

const root = createRoot(document.getElementById('root')!);
root.render(<div className="startup"><div className="startup-mark">✦</div><p>Opening your workspace…</p></div>);

async function bootstrap() {
  const config = await loadConfig();
  const auth = createAuth(config);
  const params = new URLSearchParams(window.location.search);
  if (params.has('state') && (params.has('code') || params.has('error'))) {
    try { await auth.signinRedirectCallback(); }
    finally { window.history.replaceState({}, document.title, window.location.pathname); }
  }
  let user = await auth.getUser();
  if (user?.expired) { await auth.removeUser(); user = null; }
  root.render(<App config={config} auth={auth} initialUser={user} />);
}

void bootstrap().catch(() => {
  // Authentication responses can contain sensitive values. Never log or display
  // raw identity-provider errors, tokens, or the callback query string.
  window.history.replaceState({}, document.title, window.location.pathname);
  root.render(<div className="startup"><div className="startup-mark">✦</div><h1>We couldn’t open the workspace</h1><p>Configuration or sign-in could not be completed.<br />Reload to try again, or contact the lab owner.</p><button onClick={() => window.location.reload()}>Reload workspace</button></div>);
});
