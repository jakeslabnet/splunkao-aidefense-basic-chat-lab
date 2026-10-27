export interface IntegrationView {
  label: string;
  tone: 'neutral' | 'success' | 'warning';
  detail: string;
}

const unverified: IntegrationView = {
  label: 'Not verified', tone: 'neutral',
  detail: 'No completed turn has reported this integration’s status.',
};
const cisco: Record<string, IntegrationView> = {
  unconfigured: { label: 'Awaiting credentials', tone: 'neutral', detail: 'The last turn reported that Cisco credentials are not configured.' },
  ok: { label: 'Last turn inspected', tone: 'success', detail: 'Cisco inspection succeeded for the last completed turn. Monitor-only mode does not block replies.' },
  findings: { label: 'Findings recorded', tone: 'warning', detail: 'Cisco reported findings for the last completed turn. Monitor-only mode allowed the reply.' },
  error: { label: 'Last inspection failed', tone: 'warning', detail: 'Cisco inspection failed for the last completed turn. Chat remained available.' },
};
const splunk: Record<string, IntegrationView> = {
  unconfigured: { label: 'Awaiting credentials', tone: 'neutral', detail: 'The last turn reported that Splunk credentials are not configured.' },
  accepted: { label: 'Export accepted', tone: 'neutral', detail: 'The SDK accepted the last turn’s span export. Delivery to the Splunk dashboard is unverified.' },
  error: { label: 'Last export failed', tone: 'warning', detail: 'The last turn’s telemetry export failed. Chat remained available.' },
  unconfirmed: { label: 'Export not confirmed', tone: 'neutral', detail: 'The SDK could not confirm export for the last completed turn. Dashboard delivery is unverified.' },
};

export function integrationView(service: 'cisco' | 'splunk', status: unknown): IntegrationView {
  const labels = service === 'cisco' ? cisco : splunk;
  return typeof status === 'string' && Object.hasOwn(labels, status) ? labels[status] : unverified;
}
