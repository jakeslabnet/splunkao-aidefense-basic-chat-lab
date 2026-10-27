import { test } from 'node:test';
import assert from 'node:assert/strict';
import { App, BootstraplessSynthesizer } from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { ChatStack, StorageStack } from '../infra/stacks.js';

function stacks() {
  const app = new App();
  const common = {env: {account: '774569412819', region: 'us-east-1'}, synthesizer: new BootstraplessSynthesizer()};
  const storage = new StorageStack(app, 'Storage', common);
  const chat = new ChatStack(app, 'Chat', {...common,
    settings: {account: '774569412819', region: 'us-east-1', profile: 'aidefense',
      modelId: 'amazon.nova-micro-v1:0', modelResourceArns: ['arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0'],
      initialEmail: 'jaruddy@cisco.com', monthlyBudgetUsd: 25},
    manifest: {agentKey: 'releases/abc/agent.zip', apiKey: 'releases/def/api.zip', agentVersion: 'agent-version', apiVersion: 'api-version'},
  });
  return {storage: Template.fromStack(storage), chat: Template.fromStack(chat)};
}

test('runtime is explicitly V2 S3 Python with IAM authentication and no capacity provider', () => {
  const {chat} = stacks();
  chat.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
    PlatformVersion: 'V2', ProtocolConfiguration: 'HTTP',
    AgentRuntimeArtifact: {CodeConfiguration: {Runtime: 'PYTHON_3_13', EntryPoint: ['main.py'],
      Code: {S3: Match.objectLike({Prefix: 'releases/abc/agent.zip', VersionId: 'agent-version'})}}},
    CapacityProviderConfiguration: Match.absent(), AuthorizerConfiguration: Match.absent(),
    EnvironmentVariables: Match.objectLike({
      OTEL_SEMCONV_STABILITY_OPT_IN: 'gen_ai_latest_experimental,gen_ai_span_attributes_only',
    }),
  });
  const raw = chat.toJSON();
  const runtime = Object.values(raw.Resources).find((r: any) => r.Type === 'AWS::BedrockAgentCore::Runtime') as any;
  assert.ok(Object.keys(runtime.Properties.EnvironmentVariables).every(key => !['AWS_ACCESS_KEY_ID','SPLUNK_AO_O11Y_TOKEN','CISCO_API_KEY'].includes(key)));
});

test('chat API requires Cognito scope and actually uses response streaming', () => {
  const {chat} = stacks();
  chat.hasResourceProperties('AWS::ApiGateway::Method', {HttpMethod: 'POST',
    AuthorizationType: 'COGNITO_USER_POOLS', AuthorizationScopes: ['agent-chat/invoke'],
    Integration: Match.objectLike({Type: 'AWS_PROXY', ResponseTransferMode: 'STREAM', TimeoutInMillis: 300000})});
  chat.hasResourceProperties('AWS::Cognito::UserPool', {AdminCreateUserConfig: {AllowAdminCreateUserOnly: true}});
  chat.hasResourceProperties('AWS::Cognito::UserPoolClient', {GenerateSecret: false, AllowedOAuthFlows: ['code']});
  // Cognito Lite rejects refresh-token rotation; keep the deployed tier and client settings compatible.
  chat.hasResourceProperties('AWS::Cognito::UserPool', {UserPoolTier: 'LITE'});
  chat.hasResourceProperties('AWS::Cognito::UserPoolClient', {RefreshTokenRotation: Match.absent(), ExplicitAuthFlows: ['ALLOW_USER_SRP_AUTH']});
});

test('secret containers have no generated or hardcoded credentials and storage is private', () => {
  const {storage, chat} = stacks();
  storage.resourceCountIs('AWS::SecretsManager::Secret', 2);
  storage.hasResourceProperties('AWS::SecretsManager::Secret', {Name: '/agentcore-chat-lab/cisco',
    SecretString: Match.absent(), GenerateSecretString: Match.absent()});
  for (const template of [storage, chat]) template.hasResourceProperties('AWS::S3::Bucket', {
    PublicAccessBlockConfiguration: {BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true},
    BucketEncryption: Match.anyValue(),
  });
  chat.resourceCountIs('AWS::EC2::NatGateway', 0);
  chat.resourceCountIs('AWS::EC2::Instance', 0);
});
