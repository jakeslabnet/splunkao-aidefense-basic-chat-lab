import { describe, expect, it } from 'vitest';
import { validateConfig } from './config';
const config = { region: 'us-east-1', userPoolId: 'us-east-1_test', clientId: '123abc', authDomain: 'https://test.auth.us-east-1.amazoncognito.com', redirectUri: 'https://chat.example/', logoutUri: 'https://chat.example/', apiBase: '/api' };
describe('public configuration', () => {
  it('rejects external callback destinations and insecure authentication endpoints', () => {
    expect(() => validateConfig({ ...config, redirectUri: 'https://other.example/' }, 'https://chat.example')).toThrow('this application origin');
    expect(() => validateConfig({ ...config, authDomain: 'http://test.example' }, 'https://chat.example')).toThrow('authentication origin');
  });
  it('accepts same-origin Cognito SPA configuration', () => { expect(validateConfig(config, 'https://chat.example')).toEqual(config); });
});
