import { describe, expect, it } from 'vitest';
import { integrationView } from './integrations';

describe('integration evidence display', () => {
  it('never claims success for missing, unknown, or malformed server status', () => {
    for (const status of [undefined, null, '', 'healthy', '__proto__', { status: 'ok' }]) {
      for (const service of ['cisco', 'splunk'] as const) {
        expect(integrationView(service, status)).toMatchObject({ label: 'Not verified', tone: 'neutral' });
      }
    }
  });
  it('shows missing credentials separately from recorded inspection evidence', () => {
    expect(integrationView('cisco', 'unconfigured')).toMatchObject({ label: 'Awaiting credentials', tone: 'neutral' });
    expect(integrationView('cisco', 'ok')).toMatchObject({ label: 'Last turn inspected', tone: 'success' });
    expect(integrationView('cisco', 'findings').tone).toBe('warning');
    expect(integrationView('cisco', 'error').tone).toBe('warning');
  });
  it('distinguishes SDK acceptance from dashboard delivery and export failures', () => {
    expect(integrationView('splunk', 'accepted')).toMatchObject({ label: 'Export accepted', tone: 'neutral' });
    expect(integrationView('splunk', 'accepted').detail).toContain('dashboard is unverified');
    expect(integrationView('splunk', 'unconfirmed').label).toBe('Export not confirmed');
    expect(integrationView('splunk', 'error').label).toBe('Last export failed');
    expect(integrationView('splunk', 'unconfigured').label).toBe('Awaiting credentials');
  });
});
