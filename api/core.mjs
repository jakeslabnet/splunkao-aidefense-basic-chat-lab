import { createHash, randomUUID } from 'node:crypto';

export const LIMITS = Object.freeze({ messages: 40, contentBytes: 65_536, bodyBytes: 400_000, upstreamEventBytes: 262_144 });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SCOPE = 'agent-chat/invoke';
const TRACE_ID = /^[0-9a-f]{32}$/i;
const AUTH_REASONS = new Set(['missing_claims', 'token_use', 'client', 'issuer', 'subject', 'expiry']);
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const UTC_EXPIRY = /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (0[1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d) UTC ?([1-9]\d{3})$/;

export class HttpError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.name = 'HttpError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

function badRequest(message = 'The request body is invalid.') {
  return new HttpError(400, 'INVALID_REQUEST', message);
}

function hasExactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

/** Parse only trusted Gateway claims: NumericDate or its explicit UTC date representation. */
export function parseTrustedExpiry(value) {
  if (value === undefined || value === null) return { format: 'missing', epochSeconds: undefined };
  if (typeof value === 'number') {
    return { format: 'numeric', epochSeconds: Number.isSafeInteger(value) && value >= 0 ? value : undefined };
  }
  if (typeof value !== 'string') return { format: 'other', epochSeconds: undefined };
  if (/^(?:0|[1-9]\d{0,15})$/.test(value)) {
    const seconds = Number(value);
    return { format: 'epoch_string', epochSeconds: Number.isSafeInteger(seconds) ? seconds : undefined };
  }
  const match = UTC_EXPIRY.exec(value);
  if (!match) return { format: 'other', epochSeconds: undefined };
  const [, weekday, month, dayText, hourText, minuteText, secondText, yearText] = match;
  const [year, day, hour, minute, second] = [yearText, dayText, hourText, minuteText, secondText].map(Number);
  const monthIndex = MONTHS.indexOf(month);
  const milliseconds = Date.UTC(year, monthIndex, day, hour, minute, second);
  const date = new Date(milliseconds);
  // Date.UTC normalizes invalid dates, so round-trip every calendar field and the weekday.
  const valid = date.getUTCFullYear() === year && date.getUTCMonth() === monthIndex
    && date.getUTCDate() === day && date.getUTCHours() === hour && date.getUTCMinutes() === minute
    && date.getUTCSeconds() === second && WEEKDAYS[date.getUTCDay()] === weekday;
  return { format: 'utc_date', epochSeconds: valid ? milliseconds / 1000 : undefined };
}

/** Trust only claims supplied by the API Gateway Cognito authorizer. Never decode a browser JWT here. */
export function authorize(event, config, nowSeconds = Date.now() / 1000) {
  if (!config.clientId || !config.issuer) throw new HttpError(503, 'NOT_CONFIGURED', 'Authentication is not configured.');
  const claims = event?.requestContext?.authorizer?.claims;
  const reject = (reason) => {
    const error = new HttpError(401, 'UNAUTHORIZED', 'Sign in again to continue.');
    // The reason is an application-owned enum. Claim values and tokens never enter diagnostics.
    error.reason = reason;
    throw error;
  };
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) reject('missing_claims');
  if (claims.token_use !== 'access') reject('token_use');
  if (claims.client_id !== config.clientId) reject('client');
  if (claims.iss !== config.issuer) reject('issuer');
  if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 256) reject('subject');
  const expiry = parseTrustedExpiry(claims.exp);
  if (expiry.epochSeconds === undefined || expiry.epochSeconds <= nowSeconds) reject('expiry');
  if (typeof claims.scope !== 'string' || !claims.scope.split(/\s+/).includes(SCOPE)) {
    throw new HttpError(403, 'FORBIDDEN', 'This session cannot access chat.');
  }
  return { issuer: claims.iss, subject: claims.sub };
}

export function validateChat(event) {
  const contentType = Object.entries(event?.headers ?? {}).find(([key]) => key.toLowerCase() === 'content-type')?.[1];
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Send an application/json request.');
  }
  if (typeof event?.body !== 'string' || event.body.length > LIMITS.bodyBytes * 2) throw badRequest();
  const body = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf8') : event.body;
  if (Buffer.byteLength(body) > LIMITS.bodyBytes) throw new HttpError(413, 'REQUEST_TOO_LARGE', 'The conversation is too large.');
  let parsed;
  try { parsed = JSON.parse(body); } catch { throw badRequest('Send valid JSON.'); }
  if (!hasExactKeys(parsed, ['conversationId', 'messages']) || typeof parsed.conversationId !== 'string'
    || !UUID.test(parsed.conversationId) || !Array.isArray(parsed.messages)
    || !parsed.messages.length || parsed.messages.length > LIMITS.messages) throw badRequest();
  let contentBytes = 0;
  const messages = parsed.messages.map((message) => {
    if (!hasExactKeys(message, ['role', 'content']) || !['user', 'assistant'].includes(message.role)
      || typeof message.content !== 'string' || !message.content.trim()) throw badRequest();
    contentBytes += Buffer.byteLength(message.content);
    return { role: message.role, content: message.content };
  });
  if (contentBytes > LIMITS.contentBytes) throw new HttpError(413, 'REQUEST_TOO_LARGE', 'Keep conversation text under 64 KiB.');
  if (messages.at(-1).role !== 'user') throw badRequest('The last message must be from the user.');
  return { conversationId: parsed.conversationId.toLowerCase(), messages };
}

export function deriveSession(identity, conversationId) {
  const hash = (parts) => createHash('sha256').update(JSON.stringify(parts)).digest('hex');
  return {
    userId: hash([identity.issuer, identity.subject]),
    runtimeSessionId: hash([identity.issuer, identity.subject, conversationId]),
  };
}

export function parseAppConfig(value) {
  let config;
  try { config = JSON.parse(value); } catch { throw new HttpError(503, 'NOT_CONFIGURED', 'The model is not configured.'); }
  if (typeof config?.modelId !== 'string' || !config.modelId.trim() || config.modelId.length > 2048) {
    throw new HttpError(503, 'NOT_CONFIGURED', 'The model is not configured.');
  }
  const result = { modelId: config.modelId };
  if (typeof config.cognitoClientId === 'string' && /^[a-z0-9]{1,128}$/.test(config.cognitoClientId)) {
    result.cognitoClientId = config.cognitoClientId;
  }
  return result;
}

export function encodeEvent(type, data) {
  if (!['metadata', 'delta', 'error', 'done'].includes(type)) throw new Error('INVALID_AGENT_RESPONSE');
  return `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
}

export function normalizeAgentEvent(data, requestId) {
  let value = data;
  // BedrockAgentCoreApp encodes yielded dictionaries as JSON SSE data. Accept a JSON string wrapper, too.
  for (let depth = 0; depth < 3 && typeof value === 'string'; depth += 1) {
    try { value = JSON.parse(value); } catch { throw new Error('INVALID_AGENT_RESPONSE'); }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_AGENT_RESPONSE');
  switch (value.type) {
    case 'metadata': {
      if (typeof value.modelId !== 'string' || !value.modelId || value.modelId.length > 2048
        || typeof value.traceId !== 'string' || !TRACE_ID.test(value.traceId)) throw new Error('INVALID_AGENT_RESPONSE');
      return { type: 'metadata', requestId, modelId: value.modelId, traceId: value.traceId };
    }
    case 'delta':
      if (typeof value.text !== 'string') throw new Error('INVALID_AGENT_RESPONSE');
      return { type: 'delta', text: value.text };
    case 'error':
      return { type: 'error', requestId, code: 'AGENT_ERROR', message: 'The agent could not complete the response.' };
    case 'done': {
      const ciscoStatuses = ['unconfigured', 'ok', 'findings', 'error'];
      const splunkStatuses = ['unconfigured', 'accepted', 'error', 'unconfirmed'];
      if (!ciscoStatuses.includes(value.ciscoStatus) || !splunkStatuses.includes(value.splunkStatus)) throw new Error('INVALID_AGENT_RESPONSE');
      const result = { type: 'done', requestId, ciscoStatus: value.ciscoStatus, splunkStatus: value.splunkStatus };
      if (typeof value.modelId === 'string' && value.modelId.length <= 2048) result.modelId = value.modelId;
      if (typeof value.traceId === 'string' && TRACE_ID.test(value.traceId)) result.traceId = value.traceId;
      return result;
    }
    default: throw new Error('INVALID_AGENT_RESPONSE');
  }
}

/** Parse raw SDK response bytes incrementally; split UTF-8 characters and SSE frames may span any chunk. */
export async function* parseAgentEvents(body, contentType = 'text/event-stream') {
  if (!body || !body[Symbol.asyncIterator]) throw new Error('INVALID_AGENT_RESPONSE');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  if (contentType.split(';')[0].trim().toLowerCase() === 'application/json') {
    let json = '';
    for await (const chunk of body) {
      json += decoder.decode(typeof chunk === 'string' ? Buffer.from(chunk) : chunk, { stream: true });
      if (Buffer.byteLength(json) > LIMITS.upstreamEventBytes) throw new Error('INVALID_AGENT_RESPONSE');
    }
    yield json + decoder.decode();
    return;
  }
  if (!contentType.toLowerCase().startsWith('text/event-stream')) throw new Error('INVALID_AGENT_RESPONSE');
  let buffer = '';
  let lines = [];
  let frameBytes = 0;
  const processLine = (line) => {
    if (!line) {
      const data = lines.length ? lines.join('\n') : undefined;
      lines = [];
      frameBytes = 0;
      return data;
    }
    frameBytes += Buffer.byteLength(line);
    if (frameBytes > LIMITS.upstreamEventBytes) throw new Error('INVALID_AGENT_RESPONSE');
    if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''));
    return undefined;
  };
  for await (const chunk of body) {
    buffer += decoder.decode(typeof chunk === 'string' ? Buffer.from(chunk) : chunk, { stream: true });
    let newline;
    while ((newline = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, newline).replace(/\r$/, '');
      buffer = buffer.slice(newline + 1);
      const data = processLine(line);
      if (data !== undefined) yield data;
    }
    if (Buffer.byteLength(buffer) + frameBytes > LIMITS.upstreamEventBytes) throw new Error('INVALID_AGENT_RESPONSE');
  }
  buffer += decoder.decode();
  if (buffer) processLine(buffer.replace(/\r$/, ''));
  if (lines.length) yield lines.join('\n');
}

function abortedError(signal) {
  return signal.reason instanceof Error ? signal.reason : new Error('CLIENT_DISCONNECTED');
}

export function withAbort(promise, signal) {
  if (signal.aborted) return Promise.reject(abortedError(signal));
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortedError(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

function write(stream, chunk, signal) {
  if (signal?.aborted) return Promise.reject(abortedError(signal));
  if (stream.destroyed || stream.writableEnded) return Promise.reject(new Error('CLIENT_DISCONNECTED'));
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortedError(signal));
    signal?.addEventListener('abort', onAbort, { once: true });
    stream.write(chunk, (error) => {
      signal?.removeEventListener('abort', onAbort);
      if (error) reject(error); else resolve();
    });
  });
}

const JSON_HEADERS = Object.freeze({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
const SSE_HEADERS = Object.freeze({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-store', 'X-Content-Type-Options': 'nosniff' });

/** Dependencies are injected so unit tests never send credentials or invoke AWS. */
export function createStreamingHandler({ invokeRuntime, getConfig, makeHttpStream, config, log = () => {}, deadlineMs = 270_000, heartbeatMs = 10_000, id = randomUUID }) {
  return async function streamingHandler(event, rawStream, context = {}) {
    const startedAt = Date.now();
    const requestId = id();
    let stream;
    let chat;
    let identity;
    let route;
    try {
      // The app client references the final CloudFront callback URL, so it lives in SSM to avoid a deployment dependency cycle.
      const appConfig = parseAppConfig(await getConfig());
      identity = authorize(event, { ...config, clientId: appConfig.cognitoClientId ?? config.clientId });
      route = `${event.httpMethod} ${event.path}`;
      if (route === 'GET /api/config') {
        log({ event: 'configuration_authorized', requestId,
          expiryFormat: parseTrustedExpiry(event?.requestContext?.authorizer?.claims?.exp).format });
        stream = makeHttpStream(rawStream, { statusCode: 200, headers: JSON_HEADERS });
        await write(stream, JSON.stringify({ modelId: appConfig.modelId }));
        stream.end();
        return;
      }
      if (route !== 'POST /api/chat') throw new HttpError(404, 'NOT_FOUND', 'This endpoint does not exist.');
      chat = validateChat(event);
      if (!config.runtimeArn) throw new HttpError(503, 'NOT_CONFIGURED', 'The agent is not configured.');
    } catch (error) {
      const failure = error instanceof HttpError ? error : new HttpError(503, 'CONFIGURATION_UNAVAILABLE', 'The configuration is unavailable.');
      stream ??= makeHttpStream(rawStream, { statusCode: failure.statusCode, headers: JSON_HEADERS });
      try { await write(stream, JSON.stringify({ code: failure.code, message: failure.message, requestId })); } catch { /* Disconnected client. */ }
      stream.end();
      log({ event: 'request_rejected', requestId, code: failure.code, statusCode: failure.statusCode,
        ...(failure.statusCode === 401 && AUTH_REASONS.has(failure.reason) ? {
          reason: failure.reason, expiryFormat: parseTrustedExpiry(event?.requestContext?.authorizer?.claims?.exp).format,
        } : {}) });
      return;
    }

    const { userId, runtimeSessionId } = deriveSession(identity, chat.conversationId);
    const controller = new AbortController();
    let upstream;
    let finished = false;
    let heartbeatPending = false;
    let chain = Promise.resolve();
    const enqueue = (chunk, useSignal = true) => {
      const pending = chain.then(() => write(stream, chunk, useSignal ? controller.signal : undefined));
      chain = pending.catch(() => {});
      return pending;
    };
    const onDisconnect = () => {
      if (!finished && !controller.signal.aborted) controller.abort(new Error('CLIENT_DISCONNECTED'));
    };
    rawStream.on('close', onDisconnect);
    rawStream.on('error', onDisconnect);
    const destroyUpstream = () => {
      upstream?.destroy?.();
      if (upstream?.cancel) Promise.resolve(upstream.cancel()).catch(() => {});
    };
    controller.signal.addEventListener('abort', destroyUpstream, { once: true });
    const timeRemaining = typeof context.getRemainingTimeInMillis === 'function' ? context.getRemainingTimeInMillis() : Infinity;
    const timeout = setTimeout(() => controller.abort(new Error('DEADLINE_EXCEEDED')), Math.max(1, Math.min(deadlineMs - (Date.now() - startedAt), timeRemaining - 5_000)));
    timeout.unref?.();
    stream = makeHttpStream(rawStream, { statusCode: 200, headers: SSE_HEADERS });
    const heartbeat = setInterval(() => {
      if (heartbeatPending || controller.signal.aborted) return;
      heartbeatPending = true;
      enqueue(': heartbeat\n\n').catch(onDisconnect).finally(() => { heartbeatPending = false; });
    }, heartbeatMs);
    heartbeat.unref?.();
    try {
      await enqueue(': connected\n\n');
      const payload = { requestId, conversationId: chat.conversationId, userId, messages: chat.messages };
      const response = await withAbort(invokeRuntime({ runtimeSessionId, payload, signal: controller.signal }), controller.signal);
      upstream = response.response;
      if (controller.signal.aborted) { destroyUpstream(); throw abortedError(controller.signal); }
      const iterator = parseAgentEvents(upstream, response.contentType)[Symbol.asyncIterator]();
      let terminal;
      while (true) {
        const next = await withAbort(iterator.next(), controller.signal);
        if (next.done) break;
        const agentEvent = normalizeAgentEvent(next.value, requestId);
        await enqueue(encodeEvent(agentEvent.type, agentEvent));
        if (agentEvent.type === 'done' || agentEvent.type === 'error') { terminal = agentEvent.type; break; }
      }
      if (!terminal) throw new Error('INCOMPLETE_AGENT_RESPONSE');
      log({ event: terminal === 'done' ? 'chat_completed' : 'chat_interrupted', requestId, ...(terminal === 'error' ? { code: 'AGENT_ERROR' } : {}) });
    } catch (error) {
      const code = controller.signal.aborted ? controller.signal.reason?.message : error?.message;
      if (code !== 'CLIENT_DISCONNECTED' && !rawStream.destroyed) {
        const isTimeout = code === 'DEADLINE_EXCEEDED';
        const safeError = { type: 'error', requestId, code: isTimeout ? 'DEADLINE_EXCEEDED' : 'UPSTREAM_ERROR', message: isTimeout ? 'The response timed out. Start a new request to continue.' : 'The response was interrupted. Try again when you are ready.' };
        try { await enqueue(encodeEvent('error', safeError), false); } catch { /* Disconnected client. */ }
      }
      log({ event: 'chat_interrupted', requestId, code: code === 'CLIENT_DISCONNECTED' ? 'CLIENT_DISCONNECTED' : code === 'DEADLINE_EXCEEDED' ? 'DEADLINE_EXCEEDED' : 'UPSTREAM_ERROR' });
    } finally {
      finished = true;
      clearTimeout(timeout);
      clearInterval(heartbeat);
      destroyUpstream();
      controller.signal.removeEventListener('abort', destroyUpstream);
      rawStream.removeListener('close', onDisconnect);
      rawStream.removeListener('error', onDisconnect);
      if (!stream.destroyed && !stream.writableEnded) stream.end();
    }
  };
}
