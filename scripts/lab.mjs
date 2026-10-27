#!/usr/bin/env node
// Repeatable operator tooling. AWS identity comes from the named profile; no credentials are persisted.
import { readFile, writeFile, readdir, stat } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { extname, resolve, relative } from 'node:path';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { CloudFormationClient, DescribeStacksCommand, CreateChangeSetCommand, DescribeChangeSetCommand, ExecuteChangeSetCommand, DeleteStackCommand } from '@aws-sdk/client-cloudformation';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { CloudFrontClient, CreateInvalidationCommand } from '@aws-sdk/client-cloudfront';
import { CloudWatchLogsClient, CreateLogGroupCommand, PutRetentionPolicyCommand, AssociateKmsKeyCommand } from '@aws-sdk/client-cloudwatch-logs';

const root = resolve(import.meta.dirname, '..');
process.chdir(root);
const settings = JSON.parse(await readFile('config/lab.json', 'utf8'));
const credentials = fromNodeProviderChain({profile: settings.profile});
const aws = {region: settings.region, credentials};
const cf = new CloudFormationClient(aws), s3 = new S3Client(aws), edge = new CloudFrontClient(aws);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const run = (...args) => {
  const result = spawnSync(args[0], args.slice(1), {stdio: 'inherit', cwd: root});
  if (result.status !== 0) throw new Error(`Failed: ${args.join(' ')}`);
};

async function identity() {
  const actual = await new STSClient(aws).send(new GetCallerIdentityCommand({}));
  if (actual.Account !== settings.account) throw new Error(`Wrong AWS account: ${actual.Account}; expected ${settings.account}`);
  console.log(`AWS account ${actual.Account}; region ${settings.region}; profile ${settings.profile}`);
}

async function stack(name) {
  try { return (await cf.send(new DescribeStacksCommand({StackName: name}))).Stacks[0]; }
  catch (error) { if (error.name === 'ValidationError' && /does not exist/.test(error.message)) return undefined; throw error; }
}
const outputs = value => Object.fromEntries((value?.Outputs ?? []).map(item => [item.OutputKey, item.OutputValue]));

async function deployStack(name) {
  const existing = await stack(name);
  const changeName = `deploy-${randomUUID()}`;
  await cf.send(new CreateChangeSetCommand({StackName: name, ChangeSetName: changeName,
    ChangeSetType: existing ? 'UPDATE' : 'CREATE',
    TemplateBody: await readFile(`cdk.out/${name}.template.json`, 'utf8'),
    Capabilities: ['CAPABILITY_IAM'],
    Tags: [{Key:'Project',Value:'agentcore-chat-lab'},{Key:'Environment',Value:'lab'}],
  }));
  let changes;
  for (;;) {
    changes = await cf.send(new DescribeChangeSetCommand({StackName: name, ChangeSetName: changeName}));
    if (changes.Status === 'CREATE_COMPLETE') break;
    if (changes.Status === 'FAILED') {
      if (/didn't contain changes|No updates/.test(changes.StatusReason ?? '')) return existing;
      throw new Error(changes.StatusReason);
    }
    await sleep(3000);
  }
  console.table(changes.Changes.map(item => ({action:item.ResourceChange.Action, type:item.ResourceChange.ResourceType,
    resource:item.ResourceChange.LogicalResourceId, replacement:item.ResourceChange.Replacement ?? ''})));
  await cf.send(new ExecuteChangeSetCommand({StackName:name,ChangeSetName:changeName}));
  let last;
  for (;;) {
    const value = await stack(name);
    if (last !== value.StackStatus) {console.log(`${name}: ${value.StackStatus}`);last=value.StackStatus;}
    if (['CREATE_COMPLETE','UPDATE_COMPLETE'].includes(value.StackStatus)) return value;
    if (!value.StackStatus.endsWith('_IN_PROGRESS')) throw new Error(`${name}: ${value.StackStatus}; inspect CloudFormation events`);
    await sleep(5000);
  }
}

async function* files(directory) {
  for (const name of await readdir(directory)) {
    const path = resolve(directory, name);
    if ((await stat(path)).isDirectory()) yield* files(path); else yield path;
  }
}

async function publish() {
  const out = outputs(await stack('AgentCoreChatLab'));
  if (!out.WebBucket) throw new Error('Application stack is not ready');
  const contentTypes = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8',
    '.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.json':'application/json'};
  for await (const file of files(resolve('web/dist'))) {
    const key = relative(resolve('web/dist'), file).split('\\').join('/');
    await s3.send(new PutObjectCommand({Bucket:out.WebBucket,Key:key,Body:await readFile(file),
      ContentType:contentTypes[extname(file)] ?? 'application/octet-stream',
      CacheControl:key.startsWith('assets/') ? 'public,max-age=31536000,immutable' : 'no-cache',
      ExpectedBucketOwner:settings.account}));
  }
  await s3.send(new PutObjectCommand({Bucket:out.WebBucket,Key:'app-config.json',
    Body:JSON.stringify({region:settings.region,userPoolId:out.UserPoolId,clientId:out.ClientId,
      authDomain:out.AuthDomain,redirectUri:out.WebUrl,logoutUri:out.WebUrl,apiBase:'/api'}),
    ContentType:'application/json',CacheControl:'no-store',ExpectedBucketOwner:settings.account}));
  await edge.send(new CreateInvalidationCommand({DistributionId:out.DistributionId,
    InvalidationBatch:{CallerReference:randomUUID(),Paths:{Quantity:2,Items:['/','/index.html']}}}));
  await writeFile('deployment-outputs.json',JSON.stringify(out,null,2)+'\n');
  console.log(`Chat UI: ${out.WebUrl}`);
}

async function hardenRuntimeLogs() {
  const out = outputs(await stack('AgentCoreChatLab'));
  const name = `/aws/bedrock-agentcore/runtimes/${out.RuntimeId}-DEFAULT`;
  const logs = new CloudWatchLogsClient(aws);
  try {
    await logs.send(new CreateLogGroupCommand({logGroupName:name,kmsKeyId:out.LogKeyArn,
      tags:{Project:'agentcore-chat-lab',Environment:'lab'}}));
  } catch (error) { if (error.name !== 'ResourceAlreadyExistsException') throw error; }
  await logs.send(new PutRetentionPolicyCommand({logGroupName:name,retentionInDays:7}));
  await logs.send(new AssociateKmsKeyCommand({logGroupName:name,kmsKeyId:out.LogKeyArn}));
  console.log('Runtime service log group: KMS encryption and seven-day retention applied.');
}

async function uploadArtifacts() {
  const bucket = `agentcore-chat-lab-artifacts-${settings.account}-${settings.region}`;
  const manifest = JSON.parse(await readFile('build/manifest.json','utf8'));
  for (const kind of ['agent','api']) {
    const uploaded = await s3.send(new PutObjectCommand({Bucket:bucket,Key:manifest[`${kind}Key`],
      Body:await readFile(`build/${kind}.zip`),ContentType:'application/zip',ExpectedBucketOwner:settings.account}));
    manifest[`${kind}Version`] = uploaded.VersionId;
  }
  await writeFile('build/manifest.json',JSON.stringify(manifest,null,2)+'\n');
}

async function deploy() {
  run('npm','run','check');run('npm','run','test:infra');
  run('npm','run','synth');
  await deployStack('AgentCoreChatLabStorage');
  await uploadArtifacts();
  run('npm','run','synth');
  await deployStack('AgentCoreChatLab');
  await hardenRuntimeLogs();
  await publish();
  console.log('Configure SDK secrets before validating Cisco/Splunk. See README.md.');
}

await identity();
const [command, modelId, ...resourceArns] = process.argv.slice(2);
if (command === 'deploy') await deploy();
else if (command === 'publish') await publish();
else if (command === 'status') console.log(JSON.stringify(outputs(await stack('AgentCoreChatLab')), null, 2));
else if (command === 'set-model') {
  if (!modelId || !resourceArns.length || !resourceArns.every(value => /^arn:aws:bedrock:[a-z0-9-]+:(?:\d{12})?:(?:foundation-model|inference-profile|application-inference-profile)\//.test(value))) {
    throw new Error('Usage: npm run set-model -- MODEL_ID BEDROCK_RESOURCE_ARN [ADDITIONAL_RESOURCE_ARNS...]');
  }
  settings.modelId=modelId;settings.modelResourceArns=resourceArns;
  await writeFile('config/lab.json',JSON.stringify(settings,null,2)+'\n');
  run('npm','run','synth');
  await deployStack('AgentCoreChatLab');
  console.log('Model and scoped IAM grants updated; new requests use the new configuration. Agent ZIP unchanged.');
} else if (command === 'cleanup') {
  if (!process.argv.includes('--confirm-delete-app')) throw new Error('Cleanup removes the application. Re-run with --confirm-delete-app after reviewing README retention notes.');
  await cf.send(new DeleteStackCommand({StackName:'AgentCoreChatLab'}));
  console.log('Application deletion requested. User pool, web bucket, log KMS key, artifact bucket, and SDK secrets are retained.');
} else throw new Error('Commands: deploy, publish, status, set-model, cleanup');
