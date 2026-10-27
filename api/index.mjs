import { BedrockAgentCoreClient, InvokeAgentRuntimeCommand } from '@aws-sdk/client-bedrock-agentcore';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { createStreamingHandler } from './core.mjs';

const region = process.env.AWS_REGION ?? 'us-east-1';
// Retrying an invocation could duplicate a reply after partial execution.
const runtime = new BedrockAgentCoreClient({ region, maxAttempts: 1 });
const ssm = new SSMClient({ region, maxAttempts: 2, requestHandler: { connectionTimeout: 1_000, requestTimeout: 5_000 } });
const lambdaRuntime = globalThis.awslambda;

export const streamingHandler = createStreamingHandler({
  config: {
    runtimeArn: process.env.AGENT_RUNTIME_ARN,
    clientId: process.env.COGNITO_CLIENT_ID,
    issuer: process.env.COGNITO_ISSUER,
  },
  getConfig: async () => {
    const response = await ssm.send(new GetParameterCommand({ Name: process.env.APP_CONFIG_PARAMETER ?? '/agentcore-chat-lab/config' }));
    return response.Parameter?.Value;
  },
  invokeRuntime: ({ runtimeSessionId, payload, signal }) => runtime.send(new InvokeAgentRuntimeCommand({
    agentRuntimeArn: process.env.AGENT_RUNTIME_ARN,
    qualifier: 'DEFAULT',
    runtimeSessionId,
    contentType: 'application/json',
    accept: 'text/event-stream',
    payload: Buffer.from(JSON.stringify(payload)),
  }), { abortSignal: signal }),
  makeHttpStream: (stream, metadata) => lambdaRuntime.HttpResponseStream.from(stream, metadata),
  log: (metadata) => console.info(JSON.stringify(metadata)),
});

// Lambda supplies this runtime global. Pure core helpers are imported directly by local tests.
export const handler = typeof lambdaRuntime?.streamifyResponse === 'function' ? lambdaRuntime.streamifyResponse(streamingHandler) : streamingHandler;
