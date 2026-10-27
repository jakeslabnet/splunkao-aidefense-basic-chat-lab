import { describe, expect, it } from 'vitest';
import { createChatRequest, MAX_REQUEST_BYTES } from './conversation';
import type { ChatMessage } from './conversation';
const pair = (turnId: string, status: 'complete' | 'incomplete' = 'complete', text = 'answer'): ChatMessage[] => [
  { id: `${turnId}u`, turnId, role: 'user', content: 'question', status: 'complete' },
  { id: `${turnId}a`, turnId, role: 'assistant', content: text, status },
];
describe('bounded conversation context', () => {
  it('excludes interrupted turn and retains completed turns', () => {
    expect(createChatRequest('chat', [...pair('1'), ...pair('2', 'incomplete')], 'next').messages).toEqual([
      { role: 'user', content: 'question' }, { role: 'assistant', content: 'answer' }, { role: 'user', content: 'next' },
    ]);
  });
  it('keeps alternating roles and at most 39 messages', () => {
    const request = createChatRequest('chat', Array.from({ length: 25 }, (_, i) => pair(`${i}`)).flat(), 'last');
    expect(request.messages).toHaveLength(39); expect(request.messages.at(-1)).toEqual({ role: 'user', content: 'last' });
    expect(request.messages.every((m, i) => m.role === (i % 2 ? 'assistant' : 'user'))).toBe(true);
  });
  it('prunes pairs to enforce JSON byte bound including multibyte text', () => {
    const history = [...pair('1', 'complete', '🙂'.repeat(10_000)), ...pair('2', 'complete', '🙂'.repeat(10_000))];
    const request = createChatRequest('chat', history, 'last'); expect(new TextEncoder().encode(JSON.stringify(request)).length).toBeLessThanOrEqual(MAX_REQUEST_BYTES); expect(request.messages).toHaveLength(3);
  });
  it('rejects a current message exceeding the request bound', () => { expect(() => createChatRequest('chat', [], '\n'.repeat(40_000))).toThrow('too large'); });
});
