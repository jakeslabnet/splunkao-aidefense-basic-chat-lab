import { describe, expect, it } from 'vitest';
import { consumeChatStream, readEvents } from './stream';
function stream(chunks: string[]) { const encoder = new TextEncoder(); return new ReadableStream<Uint8Array>({ start(c) { chunks.forEach((chunk) => c.enqueue(encoder.encode(chunk))); c.close(); } }); }
async function collect(chunks: string[]) { const result = []; for await (const event of readEvents(stream(chunks))) result.push(event); return result; }
describe('SSE transport', () => {
  it('handles split CRLF, comments, and multiline event data', async () => {
    expect(await collect([': heartbeat\r', '\n\r\nevent: delta\r\ndata: {\r\ndata: "text":"Hello"}\r', '\n\r', '\nevent: done\ndata: {}\n\n'])).toEqual([{ event: 'delta', data: { text: 'Hello' } }, { event: 'done', data: {} }]);
  });
  it('decodes UTF-8 split inside a character', async () => {
    const bytes = new TextEncoder().encode('event: delta\ndata: {"text":"🙂"}\n\n'); const index = bytes.findIndex((b) => b === 0xf0); const events = [];
    const split = new ReadableStream<Uint8Array>({ start(c) { c.enqueue(bytes.slice(0, index + 2)); c.enqueue(bytes.slice(index + 2)); c.close(); } });
    for await (const event of readEvents(split)) events.push(event); expect(events[0].data.text).toBe('🙂');
  });
  it('treats an ended stream without done as incomplete', async () => {
    const response = new Response(stream(['event: delta\ndata: {"text":"Partial"}\n\n']), { headers: { 'Content-Type': 'text/event-stream' } });
    await expect(consumeChatStream(response, () => undefined)).rejects.toThrow('before the reply finished');
  });
  it('does not accept unterminated done as completion', async () => {
    const response = new Response(stream(['event: done\ndata: {}\n']), { headers: { 'Content-Type': 'text/event-stream' } });
    await expect(consumeChatStream(response, () => undefined)).rejects.toThrow('before the reply finished');
  });
  it('reports the server error', async () => {
    const response = new Response(stream(['event: error\ndata: {"message":"Try again later"}\n\n']), { headers: { 'Content-Type': 'text/event-stream' } });
    await expect(consumeChatStream(response, () => undefined)).rejects.toThrow('Try again later');
  });
  it('requires SSE content type and validates delta shape', async () => {
    await expect(consumeChatStream(new Response('{}'), () => undefined)).rejects.toThrow('chat stream');
    const response = new Response(stream(['event: delta\ndata: {"text":42}\n\n']), { headers: { 'Content-Type': 'text/event-stream' } });
    await expect(consumeChatStream(response, () => undefined)).rejects.toThrow('invalid response fragment');
  });
});
