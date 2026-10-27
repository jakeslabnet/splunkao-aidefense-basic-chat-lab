export interface ServerEvent {
  event: string;
  data: Record<string, unknown>;
}

/** Incremental SSE parser, including UTF-8 chunking, CRLF, and comment heartbeats. */
export async function* readEvents(stream: ReadableStream<Uint8Array>): AsyncGenerator<ServerEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let event = 'message';
  let data: string[] = [];
  let eventSize = 0;
  let finished = false;
  try {
    while (!finished) {
      const chunk = await reader.read();
      finished = chunk.done;
      buffer += decoder.decode(chunk.value, { stream: !finished });
      if (buffer.length > 1_048_576) throw new Error('The response stream exceeded its limit.');
      let offset = 0;
      for (let index = 0; index < buffer.length; index += 1) {
        const char = buffer[index];
        if (char !== '\r' && char !== '\n') continue;
        if (char === '\r' && index === buffer.length - 1 && !finished) break;
        const line = buffer.slice(offset, index);
        if (char === '\r' && buffer[index + 1] === '\n') index += 1;
        offset = index + 1;
        if (line === '') {
          if (data.length) {
            const parsed: unknown = JSON.parse(data.join('\n'));
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
              throw new Error('The server returned an invalid stream event.');
            }
            yield { event, data: parsed as Record<string, unknown> };
          }
          event = 'message'; data = []; eventSize = 0;
        } else if (!line.startsWith(':')) {
          const colon = line.indexOf(':');
          const field = colon === -1 ? line : line.slice(0, colon);
          let value = colon === -1 ? '' : line.slice(colon + 1);
          if (value.startsWith(' ')) value = value.slice(1);
          if (field === 'event') event = value;
          if (field === 'data') {
            eventSize += value.length;
            if (eventSize > 131_072) throw new Error('The server returned an oversized stream event.');
            data.push(value);
          }
        }
      }
      buffer = buffer.slice(offset);
    }
    // An event is complete only after its terminating blank line. The caller
    // requires a done event, so interrupted/truncated streams stay incomplete.
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function consumeChatStream(
  response: Response, onEvent: (event: ServerEvent) => void,
): Promise<void> {
  if (!response.body || !response.headers.get('content-type')?.startsWith('text/event-stream')) {
    throw new Error('The server did not return a chat stream.');
  }
  for await (const event of readEvents(response.body)) {
    if (!['metadata', 'delta', 'error', 'done'].includes(event.event)) continue;
    if (event.event === 'delta' && typeof event.data.text !== 'string') {
      throw new Error('The server returned an invalid response fragment.');
    }
    onEvent(event);
    if (event.event === 'error') {
      throw new Error(typeof event.data.message === 'string'
        ? event.data.message.slice(0, 300) : 'The agent could not finish this reply.');
    }
    if (event.event === 'done') return;
  }
  throw new Error('The connection ended before the reply finished.');
}
