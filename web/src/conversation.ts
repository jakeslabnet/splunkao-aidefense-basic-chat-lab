export type MessageStatus = 'complete' | 'streaming' | 'incomplete';
export interface ChatMessage {
  id: string;
  turnId: string;
  role: 'user' | 'assistant';
  content: string;
  status: MessageStatus;
  requestId?: string;
  traceId?: string;
}
export interface WireMessage { role: 'user' | 'assistant'; content: string }
export interface ChatRequest { conversationId: string; messages: WireMessage[] }
export const MAX_REQUEST_BYTES = 65_536;

export function createChatRequest(
  conversationId: string, history: ChatMessage[], text: string,
): ChatRequest {
  // Only completed turns become future context. A stopped reply cannot silently
  // become the assistant's authoritative answer on a later request.
  const completeTurns = new Set(history.filter((m) => m.role === 'assistant'
    && m.status === 'complete').map((m) => m.turnId));
  const previous: WireMessage[] = history.filter((m) => completeTurns.has(m.turnId)
    && m.status === 'complete').map(({ role, content }) => ({ role, content }));
  const request: ChatRequest = {
    conversationId,
    messages: [...previous.slice(-38), { role: 'user', content: text }],
  };
  const encoder = new TextEncoder();
  while (encoder.encode(JSON.stringify(request)).length > MAX_REQUEST_BYTES && request.messages.length > 1) {
    request.messages.splice(0, 2);
  }
  if (encoder.encode(JSON.stringify(request)).length > MAX_REQUEST_BYTES) {
    throw new Error('This message is too large. Shorten it and try again.');
  }
  return request;
}
