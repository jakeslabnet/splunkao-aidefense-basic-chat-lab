import { useEffect, useRef, useState } from 'react';
import type { FormEvent, KeyboardEvent } from 'react';
import type { User, UserManager } from 'oidc-client-ts';
import type { AppConfig } from './config';
import { signOut } from './auth';
import { createChatRequest } from './conversation';
import type { ChatMessage } from './conversation';
import { consumeChatStream } from './stream';
import { integrationView } from './integrations';

function Icon({ name, size = 20 }: { name: 'spark' | 'plus' | 'arrow' | 'stop' | 'logout' | 'shield' | 'trace' | 'chevron'; size?: number }) {
  const paths = {
    spark: <><path d="m12 3 2.7 6.3L21 12l-6.3 2.7L12 21l-2.7-6.3L3 12l6.3-2.7L12 3Z" /><path d="m20 2 .5 1.5L22 4l-1.5.5L20 6l-.5-1.5L18 4l1.5-.5L20 2Z" /></>,
    plus: <path d="M12 5v14M5 12h14" />,
    arrow: <path d="M12 19V5m-6 6 6-6 6 6" />,
    stop: <rect x="6" y="6" width="12" height="12" rx="2" />,
    logout: <><path d="M9 5H5v14h4m5-14 7 7-7 7M8 12h13" /></>,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></>,
    trace: <><path d="M4 19V5m0 14h16M7 14l4-5 4 3 5-7" /><circle cx="11" cy="9" r="1" /></>,
    chevron: <path d="m9 5 7 7-7 7" />,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

const DEFAULT_MODEL = 'amazon.nova-micro-v1:0';
const suggestions = ['Explain how an AI agent works', 'Help me brainstorm a new idea', 'Make something complex feel simple'];

export function App({ config, auth, initialUser }: { config: AppConfig; auth: UserManager; initialUser: User | null }) {
  const [user, setUser] = useState(initialUser);
  const [modelId, setModelId] = useState(DEFAULT_MODEL);
  const [modelLoaded, setModelLoaded] = useState(false);
  const [ciscoStatus, setCiscoStatus] = useState<unknown>();
  const [splunkStatus, setSplunkStatus] = useState<unknown>();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conversationId, setConversationId] = useState(() => crypto.randomUUID());
  const abortRef = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const shouldScroll = useRef(true);

  useEffect(() => {
    const expired = () => {
      abortRef.current?.abort();
      setUser(null);
      setCiscoStatus(undefined); setSplunkStatus(undefined);
      setMessages([]);
      setError('Your session has expired. Sign in again to continue.');
      void auth.removeUser();
    };
    auth.events.addAccessTokenExpired(expired);
    return () => auth.events.removeAccessTokenExpired(expired);
  }, [auth]);

  useEffect(() => {
    if (!user || user.expired) return;
    const controller = new AbortController();
    void fetch(`${config.apiBase}/config`, {
      headers: { Authorization: `Bearer ${user.access_token}` },
      cache: 'no-store', signal: controller.signal,
    }).then(async (response) => {
      if (response.status === 401 || response.status === 403) throw new Error('Your session could not access the agent. Sign out and sign in again.');
      if (!response.ok) throw new Error('The agent configuration is temporarily unavailable.');
      const value: unknown = await response.json();
      if (!value || typeof value !== 'object' || !('modelId' in value)
        || typeof value.modelId !== 'string') throw new Error('The agent configuration is unavailable.');
      setModelId(value.modelId.slice(0, 200));
      setModelLoaded(true);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : 'The agent configuration is unavailable.');
    });
    return () => controller.abort();
  }, [user, config.apiBase]);

  useEffect(() => {
    if (shouldScroll.current) bottomRef.current?.scrollIntoView({ behavior: busy ? 'instant' : 'smooth', block: 'end' });
  }, [messages, busy]);

  useEffect(() => () => abortRef.current?.abort(), []);

  async function login() {
    setError(null); setAuthBusy(true);
    try { await auth.clearStaleState(); await auth.signinRedirect(); }
    catch { setError('Sign-in could not start. Please try again.'); setAuthBusy(false); }
  }

  async function logout() {
    abortRef.current?.abort();
    setAuthBusy(true); setMessages([]); setInput(''); setUser(null);
    setCiscoStatus(undefined); setSplunkStatus(undefined);
    try { await signOut(auth, config); }
    catch { setError('Your local session has ended. Reload the page to sign in again.'); setAuthBusy(false); }
  }

  function newChat() {
    if (abortRef.current) return;
    setMessages([]); setInput(''); setError(null); setConversationId(crypto.randomUUID());
    setCiscoStatus(undefined); setSplunkStatus(undefined);
    inputRef.current?.focus();
  }

  async function send(event: FormEvent) {
    event.preventDefault();
    const text = input.trim();
    if (!text || !user || user.expired || abortRef.current || authBusy) return;
    let request;
    try { request = createChatRequest(conversationId, messages, text); }
    catch (failure: unknown) { setError(failure instanceof Error ? failure.message : 'This message is too large.'); return; }
    const controller = new AbortController();
    abortRef.current = controller;
    const turnId = crypto.randomUUID();
    const answerId = crypto.randomUUID();
    const next: ChatMessage[] = [...messages,
      { id: crypto.randomUUID(), turnId, role: 'user', content: text, status: 'complete' },
      { id: answerId, turnId, role: 'assistant', content: '', status: 'streaming' },
    ];
    setMessages(next); setInput(''); setBusy(true); setError(null); shouldScroll.current = true;
    const updateAnswer = (fn: (message: ChatMessage) => ChatMessage) => {
      setMessages((previous) => previous.map((message) => message.id === answerId ? fn(message) : message));
    };
    const deadline = window.setTimeout(() => controller.abort('deadline'), 275_000);
    try {
      const response = await fetch(`${config.apiBase}/chat`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${user.access_token}`, 'Content-Type': 'application/json', Accept: 'text/event-stream' },
        body: JSON.stringify(request), signal: controller.signal, cache: 'no-store',
      });
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) throw new Error('Your session could not access the agent. Sign out and sign in again.');
        if (response.status === 429) throw new Error('The lab is busy. Wait a moment before sending another message.');
        throw new Error('The agent is temporarily unavailable. Please try again.');
      }
      let receivedText = false;
      await consumeChatStream(response, ({ event: eventName, data }) => {
        if (eventName === 'metadata') {
          if (typeof data.modelId === 'string') { setModelId(data.modelId.slice(0, 200)); setModelLoaded(true); }
          updateAnswer((message) => ({ ...message,
            requestId: typeof data.requestId === 'string' ? data.requestId.slice(0, 200) : undefined,
            traceId: typeof data.traceId === 'string' ? data.traceId.slice(0, 200) : undefined,
          }));
        }
        if (eventName === 'done') {
          setCiscoStatus(data.ciscoStatus);
          setSplunkStatus(data.splunkStatus);
        }
        if (eventName === 'delta') {
          receivedText = receivedText || Boolean(data.text);
          updateAnswer((message) => ({ ...message, content: message.content + (data.text as string) }));
        }
      });
      if (!receivedText) throw new Error('The agent finished without a text response.');
      updateAnswer((message) => ({ ...message, status: 'complete' }));
    } catch (failure: unknown) {
      updateAnswer((message) => ({ ...message, status: 'incomplete' }));
      if (controller.signal.aborted) {
        if (controller.signal.reason === 'deadline') setError('The reply took too long. The partial answer is marked incomplete.');
      } else {
        setError(failure instanceof Error ? failure.message : 'The connection ended before the reply finished.');
      }
    } finally {
      window.clearTimeout(deadline);
      if (abortRef.current === controller) { abortRef.current = null; setBusy(false); }
      inputRef.current?.focus();
    }
  }

  function keyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault(); event.currentTarget.form?.requestSubmit();
    }
  }

  const email = typeof user?.profile.email === 'string' ? user.profile.email : 'Signed in';
  const userInitial = email.slice(0, 1).toUpperCase();
  const displayModel = modelId === DEFAULT_MODEL ? 'Amazon Nova Micro' : modelId;
  const cisco = integrationView('cisco', ciscoStatus);
  const splunk = integrationView('splunk', splunkStatus);

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="AgentCore Chat Lab home"><span className="brand-symbol"><Icon name="spark" size={24} /></span><span>AgentCore<span className="brand-subtitle">CHAT LAB</span></span></a>
      <button className="new-chat" onClick={newChat} disabled={busy}><Icon name="plus" size={18} />New chat<span className="keyboard-hint">↵</span></button>
      <div className="sidebar-section-label">WORKSPACE</div>
      <div className="workspace-item"><span className="workspace-icon"><Icon name="spark" size={17} /></span><span>Chat playground</span><span className="workspace-dot" /></div>
      <div className="sidebar-note">A little space to explore<br />what your agent can do.</div>
      <div className="sidebar-bottom">
        <div className="integration-block">
          <div className="sidebar-section-label">INTEGRATIONS</div>
          <div className="integration-row"><Icon name="shield" size={19} /><div><span>Cisco AI Defense</span><small>Monitor only · {cisco.label}</small></div><span className={`service-dot service-${cisco.tone}`} title={cisco.detail} aria-label={cisco.detail} /></div>
          <div className="integration-row"><Icon name="trace" size={19} /><div><span>Splunk Observability</span><small>{splunk.label}</small></div><span className={`service-dot service-${splunk.tone}`} title={splunk.detail} aria-label={splunk.detail} /></div>
          <p className="integration-caption">Last completed turn. Dashboard delivery is unverified.</p>
        </div>
        <div className="sidebar-environment"><span className="environment-dot" />AWS · {config.region}<span className="lab-tag">LAB</span></div>
      </div>
    </aside>

    <main className="main-panel">
      <header className="topbar">
        <div className="breadcrumb">Workspace<span>/</span><strong>Chat playground</strong></div>
        <div className="topbar-actions"><button className="mobile-new-chat" onClick={newChat} disabled={busy} aria-label="New chat" title="New chat"><Icon name="plus" size={18} /></button><span className="private-label"><Icon name="shield" size={14} />Private access</span>{user ? <button className="account-button" onClick={() => void logout()} disabled={authBusy} title={`Sign out ${email}`}><span className="avatar-small">{userInitial}</span><span className="account-email">{email}</span><Icon name="logout" size={15} /></button> : <button className="login-small" onClick={() => void login()} disabled={authBusy}>{authBusy ? 'Connecting…' : 'Sign in'}<Icon name="chevron" size={14} /></button>}</div>
      </header>
      <div className="conversation-header"><div><span className="eyebrow">YOUR AGENT</span><h1>Chat playground</h1></div><div className="model-chip"><span className="model-dot" /><div><strong>{displayModel}</strong><small>{modelLoaded ? 'Active model' : 'Default model'}</small></div></div></div>
      <div className="conversation-scroll" ref={listRef} onScroll={() => { const el = listRef.current; if (el) shouldScroll.current = el.scrollHeight - el.scrollTop - el.clientHeight < 140; }}>
        {messages.length === 0 ? <div className="welcome">
          <div className="welcome-symbol"><Icon name="spark" size={32} /></div><div className="welcome-kicker">A CONVERSATION STARTS HERE</div><h2>What’s on your mind?</h2><p>Ask a question, work through an idea,<br className="desktop-break" /> or see where a little curiosity takes you.</p>
          <div className="suggestions">{suggestions.map((suggestion) => <button key={suggestion} onClick={() => { setInput(suggestion); inputRef.current?.focus(); }} disabled={!user}>{suggestion}<Icon name="chevron" size={16} /></button>)}</div>
          {!user && <div className="sign-in-card"><span className="sign-in-icon"><Icon name="shield" size={21} /></span><div><strong>Your workspace is invite only</strong><p>Sign in with your invited account to start chatting.</p></div><button onClick={() => void login()} disabled={authBusy}>{authBusy ? 'Connecting…' : 'Sign in'}<Icon name="chevron" size={16} /></button></div>}
        </div> : <div className="message-list" role="log" aria-label="Chat conversation" aria-live="polite" aria-relevant="additions text">{messages.map((message) => <article key={message.id} className={`message message-${message.role}`}><div className={`message-avatar ${message.role === 'assistant' ? 'agent-avatar' : ''}`}>{message.role === 'assistant' ? <Icon name="spark" size={19} /> : userInitial}</div><div className="message-body"><div className="message-label">{message.role === 'assistant' ? 'Agent' : 'You'}{message.status === 'streaming' && <span className="message-state">Thinking<span className="thinking-dots">…</span></span>}{message.status === 'incomplete' && <span className="incomplete-badge">Incomplete</span>}</div><div className="message-content">{message.content || (message.status === 'streaming' ? <span className="waiting-line">Preparing a reply<span className="thinking-dots">…</span></span> : 'Reply stopped before any text arrived.')}{message.status === 'streaming' && message.content && <span className="typing-cursor" />}</div>{message.requestId && <details className="request-details"><summary>Request details</summary><dl><dt>Request</dt><dd>{message.requestId}</dd>{message.traceId && <><dt>Trace</dt><dd>{message.traceId}</dd></>}</dl></details>}</div></article>)}</div>}
        <div ref={bottomRef} />
      </div>
      <div className="composer-area">{error && <div className="error-banner" role="alert"><span>{error}</span><button onClick={() => setError(null)} aria-label="Dismiss notification">×</button></div>}<form className={`composer ${!user ? 'composer-disabled' : ''}`} onSubmit={(event) => void send(event)}><label htmlFor="message" className="sr-only">Message your agent</label><textarea id="message" ref={inputRef} rows={2} maxLength={12_000} placeholder={user ? 'Message your agent…' : 'Sign in to start a conversation'} value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={keyDown} disabled={!user || busy || authBusy} /><div className="composer-toolbar"><span>{busy ? 'Replying…' : 'Enter to send · Shift + Enter for a new line'}</span>{busy ? <button type="button" className="send-button stop-button" onClick={() => abortRef.current?.abort()} aria-label="Stop generating reply"><Icon name="stop" size={17} /><span>Stop</span></button> : <button className="send-button" type="submit" disabled={!user || !input.trim() || authBusy} aria-label="Send message"><Icon name="arrow" size={20} /></button>}</div></form><p className="composer-note">Conversations stay in this tab. When configured, Cisco and Splunk receive prompts and replies for this demo.</p></div>
      <footer className="page-footer"><span>Powered by Amazon Bedrock AgentCore</span><span>V2 runtime<span className="footer-separator">·</span>microVM</span></footer>
    </main>
  </div>;
}
