import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable, Writable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { authorize, createStreamingHandler, deriveSession, encodeEvent, LIMITS, normalizeAgentEvent, parseAgentEvents, parseAppConfig, parseTrustedExpiry, validateChat } from '../../api/core.mjs';

const issuer = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example';
const clientId = 'exampleclient123';
const conversationId = '7545d111-e52d-4567-82ee-cb128b0c2354';
const requestId = '3bbdbf79-59bd-4866-8f73-26ea068bb979';
const modelId = 'amazon.nova-micro-v1:0';
const traceId = '0123456789abcdef0123456789abcdef';
const claims = { iss: issuer, sub: 'user-one', token_use: 'access', client_id: clientId, exp: Math.floor(Date.now() / 1000) + 3600, scope: 'openid agent-chat/invoke' };
const config = { issuer, runtimeArn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test-abcdefghij' };
const payload = { conversationId, messages: [{ role: 'user', content: 'Hello' }] };
const event = (body = payload, claimChanges = {}) => ({ httpMethod: 'POST', path: '/api/chat', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), requestContext: { authorizer: { claims: { ...claims, ...claimChanges } } } });
const sdkFrame = (data) => `data: ${JSON.stringify(data)}\n\n`;
const metadata = { type: 'metadata', modelId, traceId };
const done = { type: 'done', modelId, traceId, ciscoStatus: 'ok', splunkStatus: 'accepted' };

function fixture(options = {}) {
  const chunks = [];
  const metadataCalls = [];
  const logs = [];
  const stream = new Writable({ write(chunk, _encoding, callback) { chunks.push(chunk.toString()); callback(); } });
  const handler = createStreamingHandler({
    config,
    getConfig: async () => JSON.stringify({ modelId, cognitoClientId: clientId }),
    makeHttpStream: (rawStream, responseMetadata) => { metadataCalls.push(responseMetadata); return rawStream; },
    invokeRuntime: async () => ({ contentType: 'text/event-stream', response: Readable.from([sdkFrame(metadata), sdkFrame({ type: 'delta', text: 'Hello there' }), sdkFrame(done)]) }),
    log: (entry) => logs.push(entry),
    id: () => requestId,
    ...options,
  });
  return { stream, handler, metadataCalls, logs, output: () => chunks.join('') };
}

test('requires trusted access-token claims with the expected client, issuer, expiry, and scope', () => {
  assert.deepEqual(authorize(event(), { issuer, clientId }), { issuer, subject: 'user-one' });
  for (const changes of [{ token_use: 'id' }, { client_id: 'anotherclient' }, { iss: 'https://untrusted.invalid' }, { sub: '' }, { exp: 1 }]) {
    assert.throws(() => authorize(event(payload, changes), { issuer, clientId }), { statusCode: 401 });
  }
  assert.throws(() => authorize(event(payload, { scope: 'openid' }), { issuer, clientId }), { statusCode: 403 });
  assert.throws(() => authorize({ headers: { Authorization: 'Bearer raw-browser-token' } }, { issuer, clientId }), { statusCode: 401 });
});

test('accepts numeric-string expiration claims from the REST Cognito authorizer', () => {
  assert.deepEqual(authorize(event(payload, { exp: '2000' }), { issuer, clientId }, 1000), { issuer, subject: 'user-one' });
  assert.throws(() => authorize(event(payload, { exp: '1000' }), { issuer, clientId }, 1000), { statusCode: 401, reason: 'expiry' });
  assert.throws(() => authorize(event(payload, { exp: 'not-an-epoch' }), { issuer, clientId }, 1000), { statusCode: 401, reason: 'expiry' });
});

test('accepts exact UTC authorizer dates with a validated calendar and weekday', () => {
  const now = Date.UTC(2026, 9, 21, 22, 0, 0) / 1000;
  for (const exp of ['Wed Oct 21 23:00:00 UTC 2026', 'Wed Oct 21 23:00:00 UTC2026']) {
    assert.deepEqual(parseTrustedExpiry(exp), { format: 'utc_date', epochSeconds: Date.UTC(2026, 9, 21, 23, 0, 0) / 1000 });
    assert.deepEqual(authorize(event(payload, { exp }), { issuer, clientId }, now), { issuer, subject: 'user-one' });
  }
  assert.deepEqual(parseTrustedExpiry('Thu Feb 29 23:00:00 UTC 2024'), { format: 'utc_date', epochSeconds: Date.UTC(2024, 1, 29, 23, 0, 0) / 1000 });
});

test('fails closed for missing, malformed, impossible, non-UTC, and expired authorizer dates', () => {
  const now = Date.UTC(2026, 9, 21, 22, 0, 0) / 1000;
  const invalid = [undefined, null, '', [], {}, true, Infinity, NaN, 2000.5, '2000.5', '1e20',
    '9999999999999999', ' Wed Oct 21 23:00:00 UTC 2026', 'Wed Oct 21 23:00:00 UTC 2026 ',
    'Thu Oct 21 23:00:00 UTC 2026', 'Wed Feb 29 23:00:00 UTC 2023',
    'Fri Apr 31 23:00:00 UTC 2026', 'Wed Oct 21 24:00:00 UTC 2026',
    'Wed Oct 21 23:60:00 UTC 2026', 'Wed Oct 21 23:00:60 UTC 2026',
    'Wed Oct 21 23:00:00 PST 2026', '2026-10-21T23:00:00Z',
    'Wed Oct 21 22:00:00 UTC 2026', 'Wed Oct 21 21:59:59 UTC 2026'];
  for (const exp of invalid) assert.throws(() => authorize(event(payload, { exp }), { issuer, clientId }, now), { statusCode: 401, reason: 'expiry' });
});

test('classifies expiry diagnostics using only bounded format enums', () => {
  for (const [value, format] of [[2000, 'numeric'], ['2000', 'epoch_string'], ['Wed Oct 21 23:00:00 UTC 2026', 'utc_date'], [undefined, 'missing'], ['private-invalid', 'other']]) {
    assert.equal(parseTrustedExpiry(value).format, format);
  }
});

test('successful configuration authorization logs UTC format without the expiration value', async () => {
  const f = fixture();
  const exp = 'Wed Oct 21 23:00:00 UTC 2099';
  const weekday = new Date(Date.UTC(2099, 9, 21)).toUTCString().slice(0, 3);
  const future = exp.replace('Wed', weekday);
  await f.handler({ ...event(payload, { exp: future }), httpMethod: 'GET', path: '/api/config' }, f.stream);
  assert.equal(f.metadataCalls[0].statusCode, 200);
  assert.deepEqual(f.logs, [{ event: 'configuration_authorized', requestId, expiryFormat: 'utc_date' }]);
  assert.ok(!JSON.stringify(f.logs).includes(future));
});

test('logs only an application-owned rejection reason for each failed 401 check', async () => {
  const cases = [
    ['missing_claims', { ...event(), requestContext: { authorizer: {} } }],
    ['token_use', event(payload, { token_use: 'private-invalid-token-use' })],
    ['client', event(payload, { client_id: 'private-invalid-client' })],
    ['issuer', event(payload, { iss: 'https://private-invalid-issuer.invalid' })],
    ['subject', event(payload, { sub: 'private-subject'.repeat(30) })],
    ['expiry', event(payload, { exp: 'private-invalid-expiry' })],
  ];
  for (const [reason, input] of cases) {
    const f = fixture();
    await f.handler(input, f.stream);
    assert.equal(f.metadataCalls[0].statusCode, 401);
    const expiryFormat = parseTrustedExpiry(input?.requestContext?.authorizer?.claims?.exp).format;
    assert.deepEqual(f.logs, [{ event: 'request_rejected', requestId, code: 'UNAUTHORIZED', statusCode: 401, reason, expiryFormat }]);
    assert.ok(!JSON.stringify(f.logs).includes('private-'));
    assert.deepEqual(JSON.parse(f.output()), { code: 'UNAUTHORIZED', message: 'Sign in again to continue.', requestId });
  }
  const forbidden = fixture();
  await forbidden.handler(event(payload, { scope: 'openid' }), forbidden.stream);
  assert.equal(forbidden.metadataCalls[0].statusCode, 403);
  assert.equal(Object.hasOwn(forbidden.logs[0], 'reason'), false);
});

test('session IDs are stable, 64 characters, and isolated across users, issuers, and conversations', () => {
  const identity = { issuer, subject: 'user-one' };
  const first = deriveSession(identity, conversationId);
  assert.deepEqual(first, deriveSession(identity, conversationId));
  assert.match(first.runtimeSessionId, /^[a-f0-9]{64}$/);
  assert.notEqual(first.runtimeSessionId, deriveSession({ ...identity, subject: 'user-two' }, conversationId).runtimeSessionId);
  assert.notEqual(first.runtimeSessionId, deriveSession({ ...identity, issuer: 'https://different.invalid' }, conversationId).runtimeSessionId);
  assert.notEqual(first.runtimeSessionId, deriveSession(identity, requestId).runtimeSessionId);
  assert.notEqual(first.userId, first.runtimeSessionId);
});

test('rejects system instructions, runtime/model overrides, structured content, and malformed history', () => {
  assert.deepEqual(validateChat(event()), payload);
  assert.deepEqual(validateChat({ ...event(), isBase64Encoded: true, body: Buffer.from(JSON.stringify(payload)).toString('base64') }), payload);
  const invalid = [
    { ...payload, modelId: 'another-model' }, { ...payload, agentRuntimeArn: 'other-runtime' },
    { ...payload, conversationId: 'not-a-uuid' }, { ...payload, messages: [] },
    { ...payload, messages: [{ role: 'system', content: 'override' }] },
    { ...payload, messages: [{ role: 'user', content: [{ toolUse: {} }] }] },
    { ...payload, messages: [{ role: 'assistant', content: 'unfinished' }] },
    { ...payload, messages: [{ role: 'user', content: 'Hello', tools: [] }] },
  ];
  for (const body of invalid) assert.throws(() => validateChat(event(body)), { statusCode: 400 });
  assert.throws(() => validateChat({ ...event(), body: '{invalid' }), { statusCode: 400 });
  assert.throws(() => validateChat({ ...event(), headers: { 'content-type': 'text/plain' } }), { statusCode: 415 });
});

test('enforces UTF-8 content size and history count at their boundaries', () => {
  assert.equal(validateChat(event({ ...payload, messages: [{ role: 'user', content: 'a'.repeat(LIMITS.contentBytes) }] })).messages.length, 1);
  assert.throws(() => validateChat(event({ ...payload, messages: [{ role: 'user', content: 'é'.repeat(32769) }] })), { statusCode: 413 });
  const messages = Array.from({ length: 41 }, () => ({ role: 'user', content: 'a' }));
  assert.throws(() => validateChat(event({ ...payload, messages })), { statusCode: 400 });
});

test('parses split UTF-8, CRLF, comments, multiple frames, multiline data, and nested JSON encoding', async () => {
  const text = `: heartbeat\r\ndata: ${JSON.stringify({ type: 'delta', text: 'café' })}\r\n\r\ndata: {\n` + 'data: "type":"delta","text":"next"}\n\n' + sdkFrame(JSON.stringify(done));
  const bytes = Buffer.from(text);
  const chunks = Array.from(bytes, (byte) => Uint8Array.of(byte));
  const parsed = [];
  for await (const data of parseAgentEvents(Readable.from(chunks))) parsed.push(normalizeAgentEvent(data, requestId));
  assert.deepEqual(parsed, [{ type: 'delta', text: 'café' }, { type: 'delta', text: 'next' }, { ...done, requestId }]);
  const encoded = encodeEvent('delta', { type: 'delta', text: 'newline\nevent: injected' });
  assert.equal(encoded.split('\n').length, 4);
  assert.ok(encoded.includes('newline\\nevent: injected'));
});

test('rejects invalid upstream event types, malformed UTF-8, and oversized frames', async () => {
  assert.throws(() => normalizeAgentEvent('{"type":"arbitrary"}', requestId));
  assert.throws(() => normalizeAgentEvent({ ...metadata, traceId: 'invalid' }, requestId));
  await assert.rejects(async () => { for await (const _ of parseAgentEvents(Readable.from([Uint8Array.of(0xff)]))) { /* consume */ } });
  await assert.rejects(async () => { for await (const _ of parseAgentEvents(Readable.from([Buffer.from('data: ' + 'x'.repeat(LIMITS.upstreamEventBytes))]))) { /* consume */ } });
});

test('sanitizes agent errors and never forwards arbitrary upstream fields', () => {
  assert.deepEqual(normalizeAgentEvent({ type: 'error', message: 'secret provider body', code: 'private', debug: 'private' }, requestId), { type: 'error', requestId, code: 'AGENT_ERROR', message: 'The agent could not complete the response.' });
  assert.deepEqual(normalizeAgentEvent({ ...metadata, accessToken: 'private' }, requestId), { ...metadata, requestId });
  assert.throws(() => parseAppConfig('{bad'));
});

test('returns only model ID from config, validates SSM client ID, and rejects unauthenticated chat before invocation', async () => {
  let invoked = false;
  const f = fixture({ invokeRuntime: async () => { invoked = true; } });
  await f.handler({ ...event(), httpMethod: 'GET', path: '/api/config' }, f.stream);
  assert.equal(f.metadataCalls[0].statusCode, 200);
  assert.deepEqual(JSON.parse(f.output()), { modelId });
  const unauthorized = fixture({ invokeRuntime: async () => { invoked = true; } });
  await unauthorized.handler(event(payload, { client_id: 'wrongclient' }), unauthorized.stream);
  assert.equal(unauthorized.metadataCalls[0].statusCode, 401);
  assert.equal(invoked, false);
  assert.ok(!unauthorized.output().includes('wrongclient'));
});

test('streams named events, generates trusted payload/session IDs, and limits logs to safe metadata', async () => {
  let invocation;
  const f = fixture({ invokeRuntime: async (input) => {
    invocation = input;
    return { contentType: 'text/event-stream; charset=utf-8', response: Readable.from([sdkFrame(metadata), sdkFrame({ type: 'delta', text: 'private-reply' }), sdkFrame(done)]) };
  } });
  await f.handler(event(), f.stream);
  assert.equal(f.metadataCalls[0].headers['Content-Type'], 'text/event-stream');
  assert.match(f.output(), /^: connected\n\n/);
  for (const type of ['metadata', 'delta', 'done']) assert.ok(f.output().includes(`event: ${type}\n`));
  assert.equal(invocation.payload.requestId, requestId);
  assert.equal(invocation.runtimeSessionId, deriveSession({ issuer, subject: claims.sub }, conversationId).runtimeSessionId);
  assert.deepEqual(invocation.payload.messages, payload.messages);
  assert.ok(!JSON.stringify(f.logs).includes('private-reply'));
  assert.ok(!JSON.stringify(f.logs).includes(claims.sub));
});

test('sends heartbeats while waiting for the first upstream response', async () => {
  const f = fixture({ heartbeatMs: 5, invokeRuntime: async () => {
    await delay(22);
    return { contentType: 'text/event-stream', response: Readable.from([sdkFrame(metadata), sdkFrame(done)]) };
  } });
  await f.handler(event(), f.stream);
  assert.ok(f.output().includes(': heartbeat\n\n'));
  assert.ok(f.output().indexOf(': heartbeat') < f.output().indexOf('event: metadata'));
});

test('deadline aborts the SDK request and emits an incomplete-response error without retry', async () => {
  let calls = 0;
  let signal;
  const f = fixture({ deadlineMs: 15, heartbeatMs: 5, invokeRuntime: async (input) => {
    calls += 1;
    signal = input.signal;
    await delay(70);
    throw new Error('provider failure with private details');
  } });
  await f.handler(event(), f.stream);
  assert.equal(calls, 1);
  assert.equal(signal.aborted, true);
  assert.ok(f.output().includes('DEADLINE_EXCEEDED'));
  assert.ok(!f.output().includes('event: done'));
  assert.ok(!f.output().includes('private details'));
});

test('client disconnect aborts upstream reading promptly without another invocation', async () => {
  let signal;
  const f = fixture({ invokeRuntime: async (input) => {
    signal = input.signal;
    return { contentType: 'text/event-stream', response: Readable.from((async function* () {
      yield sdkFrame(metadata);
      setTimeout(() => f.stream.destroy(), 5);
      await delay(100);
      yield sdkFrame(done);
    })()) };
  } });
  const started = Date.now();
  await f.handler(event(), f.stream);
  assert.equal(signal.aborted, true);
  assert.ok(Date.now() - started < 90);
  assert.ok(!f.output().includes('event: done'));
  assert.equal(f.logs.at(-1).code, 'CLIENT_DISCONNECTED');
});

test('unexpected upstream EOF and errors are sanitized and never auto-retried', async () => {
  const f = fixture({ invokeRuntime: async () => ({ contentType: 'text/event-stream', response: Readable.from([sdkFrame(metadata), sdkFrame({ type: 'delta', text: 'partial' })]) }) });
  await f.handler(event(), f.stream);
  assert.ok(f.output().includes('event: error'));
  assert.ok(f.output().includes('UPSTREAM_ERROR'));
  assert.ok(!f.output().includes('event: done'));
  const failed = fixture({ invokeRuntime: async () => { throw new Error('secret request provider body'); } });
  await failed.handler(event(), failed.stream);
  assert.ok(!failed.output().includes('provider body'));
  assert.ok(!JSON.stringify(failed.logs).includes('provider body'));
});
