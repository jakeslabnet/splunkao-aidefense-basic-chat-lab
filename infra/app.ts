import { readFileSync, existsSync } from 'node:fs';
import { App, BootstraplessSynthesizer, Tags } from 'aws-cdk-lib';
import { StorageStack, ChatStack } from './stacks.js';

const app = new App();
const settings = JSON.parse(readFileSync('config/lab.json', 'utf8'));
const manifest = existsSync('build/manifest.json')
  ? JSON.parse(readFileSync('build/manifest.json', 'utf8'))
  : { agentKey: 'synth-only/agent.zip', apiKey: 'synth-only/api.zip' };
const common = {
  env: { account: settings.account, region: settings.region },
  synthesizer: new BootstraplessSynthesizer(),
};
new StorageStack(app, 'AgentCoreChatLabStorage', common);
new ChatStack(app, 'AgentCoreChatLab', { ...common, settings, manifest });
Tags.of(app).add('Project', 'agentcore-chat-lab');
Tags.of(app).add('Environment', 'lab');

