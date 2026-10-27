import {
  Stack, StackProps, CfnOutput, Fn, Duration, RemovalPolicy,
  aws_s3 as s3, aws_secretsmanager as secretsmanager, aws_iam as iam,
  aws_bedrockagentcore as agentcore, aws_logs as logs, aws_kms as kms,
  aws_lambda as lambda, aws_apigateway as apigateway, aws_cognito as cognito,
  aws_cloudfront as cloudfront, aws_cloudfront_origins as origins,
  aws_ssm as ssm, aws_budgets as budgets, aws_cloudwatch as cloudwatch,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface Settings {
  account: string; region: string; profile: string; modelId: string;
  modelResourceArns: string[]; initialEmail: string; monthlyBudgetUsd: number;
}
export interface Manifest { agentKey: string; apiKey: string; agentVersion?: string; apiVersion?: string }
const PARAMETER = '/agentcore-chat-lab/config';
const RUNTIME = 'agentcore_chat_lab';

export class StorageStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);
    const artifacts = new s3.Bucket(this, 'Artifacts', {
      bucketName: `agentcore-chat-lab-artifacts-${this.account}-${this.region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true, versioned: true, removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [{ abortIncompleteMultipartUploadAfter: Duration.days(1) }],
    });
    new CfnOutput(this, 'ArtifactBucket', { value: artifacts.bucketName });
    for (const [label, suffix] of [['Cisco', 'cisco'], ['Splunk', 'splunk']] as const) {
      // Omit both value-generation properties: credentials are populated securely later.
      const secret = new secretsmanager.CfnSecret(this, `${label}Secret`, {
        name: `/agentcore-chat-lab/${suffix}`,
        description: `${label} SDK credentials for AgentCore Chat Lab; populate in Secrets Manager`,
      });
      secret.applyRemovalPolicy(RemovalPolicy.RETAIN);
      new CfnOutput(this, `${label}SecretArn`, {
        value: secret.ref, exportName: `AgentCoreChatLab-${label}SecretArn`,
      });
    }
  }
}

export class ChatStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps & {settings: Settings; manifest: Manifest}) {
    super(scope, id, props);
    const { settings, manifest } = props;
    const artifactBucket = s3.Bucket.fromBucketName(this, 'ArtifactSource',
      `agentcore-chat-lab-artifacts-${this.account}-${this.region}`);
    const ciscoArn = Fn.importValue('AgentCoreChatLab-CiscoSecretArn');
    const splunkArn = Fn.importValue('AgentCoreChatLab-SplunkSecretArn');
    const parameterArn = this.formatArn({ service: 'ssm', resource: 'parameter', resourceName: PARAMETER.slice(1) });
    const runtimeLogPrefix = `/aws/bedrock-agentcore/runtimes/${RUNTIME}-`;
    const runtimeLogArn = `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:${runtimeLogPrefix}*`;
    const logKey = new kms.Key(this, 'LogKey', {
      enableKeyRotation: true, description: 'AgentCore Chat Lab logs',
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });
    logKey.addToResourcePolicy(new iam.PolicyStatement({
      principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:DescribeKey'],
      resources: ['*'],
      conditions: { ArnLike: { 'kms:EncryptionContext:aws:logs:arn': [
        runtimeLogArn, `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:/aws/lambda/agentcore-chat-lab-api`,
        `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:/aws/apigateway/agentcore-chat-lab`,
      ] } },
    }));
    const runtimeRole = new iam.Role(this, 'RuntimeRole', {
      description: 'Only the selected Bedrock model, chat configuration, and two SDK secrets',
      assumedBy: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com', {
        conditions: {
          StringEquals: {'aws:SourceAccount': this.account},
          ArnLike: {'aws:SourceArn': `arn:${this.partition}:bedrock-agentcore:${this.region}:${this.account}:runtime/${RUNTIME}-*`},
        },
      }),
    });
    runtimeRole.addToPolicy(new iam.PolicyStatement({
      actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'], resources: settings.modelResourceArns,
    }));
    runtimeRole.addToPolicy(new iam.PolicyStatement({ actions: ['ssm:GetParameter'], resources: [parameterArn] }));
    runtimeRole.addToPolicy(new iam.PolicyStatement({ actions: ['secretsmanager:GetSecretValue'], resources: [ciscoArn, splunkArn] }));
    runtimeRole.addToPolicy(new iam.PolicyStatement({
      actions: ['s3:GetObject', 's3:GetObjectVersion'], resources: [artifactBucket.arnForObjects(manifest.agentKey)],
    }));
    runtimeRole.addToPolicy(new iam.PolicyStatement({
      actions: ['logs:CreateLogGroup', 'logs:DescribeLogStreams', 'logs:CreateLogStream', 'logs:PutLogEvents'],
      resources: [runtimeLogArn, `${runtimeLogArn}:*`],
    }));
    const runtime = new agentcore.CfnRuntime(this, 'Runtime', {
      agentRuntimeName: RUNTIME,
      description: 'Nova Micro Strands chat, Cisco monitor-only inspection, and Splunk Agent Observability',
      platformVersion: 'V2',
      agentRuntimeArtifact: { codeConfiguration: {
        code: { s3: { bucket: artifactBucket.bucketName, prefix: manifest.agentKey, versionId: manifest.agentVersion } },
        runtime: 'PYTHON_3_13', entryPoint: ['main.py'],
      } },
      networkConfiguration: {networkMode: 'PUBLIC'},
      protocolConfiguration: 'HTTP',
      roleArn: runtimeRole.roleArn,
      lifecycleConfiguration: { idleRuntimeSessionTimeout: 300, maxLifetime: 1800 },
      environmentVariables: {
        APP_CONFIG_PARAMETER: PARAMETER, CISCO_SECRET_ARN: ciscoArn, SPLUNK_SECRET_ARN: splunkArn,
        OTEL_SEMCONV_STABILITY_OPT_IN: 'gen_ai_latest_experimental,gen_ai_span_attributes_only',
        OTEL_SERVICE_NAME: 'agentcore-chat-lab',
        DISABLE_ADOT_OBSERVABILITY: 'true',
        CISCO_INSPECTION_ORIGIN: 'https://us.api.inspect.aidefense.security.cisco.com',
        SPLUNK_REALM: 'us1',
      },
    });
    // Runtime needs the permissions before V2 prepares and snapshots the application.
    runtime.node.addDependency(runtimeRole.node.findChild('DefaultPolicy'));

    const pool = new cognito.UserPool(this, 'Users', {
      userPoolName: 'agentcore-chat-lab', selfSignUpEnabled: false,
      signInAliases: {email: true}, signInCaseSensitive: false,
      featurePlan: cognito.FeaturePlan.LITE,
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      mfa: cognito.Mfa.OPTIONAL, mfaSecondFactor: {otp: true, sms: false},
      passwordPolicy: { minLength: 14, requireDigits: true, requireLowercase: true,
        requireUppercase: true, requireSymbols: true, tempPasswordValidity: Duration.days(7) },
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });
    const domain = pool.addDomain('HostedLogin', {
      cognitoDomain: {domainPrefix: `agentcore-chat-lab-${this.account}`},
      managedLoginVersion: cognito.ManagedLoginVersion.CLASSIC_HOSTED_UI,
    });
    const invokeScope = new cognito.ResourceServerScope({scopeName: 'invoke', scopeDescription: 'Invoke chat'});
    const resourceServer = pool.addResourceServer('ChatScope', {identifier: 'agent-chat', scopes: [invokeScope]});
    const apiLog = new logs.LogGroup(this, 'ApiLogs', {
      logGroupName: '/aws/lambda/agentcore-chat-lab-api', retention: logs.RetentionDays.ONE_WEEK,
      encryptionKey: logKey, removalPolicy: RemovalPolicy.DESTROY,
    });
    const apiRole = new iam.Role(this, 'ApiRole', {assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com')});
    apiLog.grantWrite(apiRole);
    apiRole.addToPolicy(new iam.PolicyStatement({actions: ['ssm:GetParameter'], resources: [parameterArn]}));
    apiRole.addToPolicy(new iam.PolicyStatement({actions: ['bedrock-agentcore:InvokeAgentRuntime'],
      resources: [runtime.attrAgentRuntimeArn, `${runtime.attrAgentRuntimeArn}/runtime-endpoint/DEFAULT`]}));
    const adapter = new lambda.Function(this, 'Adapter', {
      functionName: 'agentcore-chat-lab-api', runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64, handler: 'index.handler',
      code: lambda.Code.fromBucket(artifactBucket, manifest.apiKey, manifest.apiVersion ?? 'synth-only'),
      role: apiRole, logGroup: apiLog, memorySize: 256, timeout: Duration.seconds(300),
      reservedConcurrentExecutions: 5,
      environment: { AGENT_RUNTIME_ARN: runtime.attrAgentRuntimeArn, APP_CONFIG_PARAMETER: PARAMETER,
        COGNITO_ISSUER: `https://cognito-idp.${this.region}.amazonaws.com/${pool.userPoolId}`, NODE_OPTIONS: '--enable-source-maps' },
    });
    const rest = new apigateway.RestApi(this, 'Api', {
      restApiName: 'agentcore-chat-lab', endpointTypes: [apigateway.EndpointType.REGIONAL],
      cloudWatchRole: false,
      deployOptions: {stageName: 'lab', throttlingRateLimit: 2, throttlingBurstLimit: 5,
        dataTraceEnabled: false, loggingLevel: apigateway.MethodLoggingLevel.OFF, tracingEnabled: false},
    });
    const authorizer = new apigateway.CognitoUserPoolsAuthorizer(this, 'Authorizer', {
      cognitoUserPools: [pool], identitySource: 'method.request.header.Authorization',
    });
    const methods = {authorizationType: apigateway.AuthorizationType.COGNITO,
      authorizer, authorizationScopes: ['agent-chat/invoke']};
    const apiResource = rest.root.addResource('api');
    apiResource.addResource('config').addMethod('GET', new apigateway.LambdaIntegration(adapter, {
      responseTransferMode: apigateway.ResponseTransferMode.STREAM,
    }), methods);
    const chat = apiResource.addResource('chat');
    chat.addMethod('POST', new apigateway.LambdaIntegration(adapter, {
      responseTransferMode: apigateway.ResponseTransferMode.STREAM,
      timeout: Duration.seconds(300),
    }), methods);

    const web = new s3.Bucket(this, 'Web', {
      bucketName: `agentcore-chat-lab-web-${this.account}-${this.region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED, enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
    });
    const securityHeaders = new cloudfront.ResponseHeadersPolicy(this, 'Headers', {
      securityHeadersBehavior: {
        strictTransportSecurity: {accessControlMaxAge: Duration.days(365), includeSubdomains: true, override: true},
        contentTypeOptions: {override: true}, frameOptions: {frameOption: cloudfront.HeadersFrameOption.DENY, override: true},
        referrerPolicy: {referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER, override: true},
        contentSecurityPolicy: {override: true, contentSecurityPolicy:
          `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://cognito-idp.${this.region}.amazonaws.com https://${domain.domainName}.auth.${this.region}.amazoncognito.com; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self' https://${domain.domainName}.auth.${this.region}.amazoncognito.com`},
      },
    });
    const distribution = new cloudfront.Distribution(this, 'CloudFront', {
      defaultRootObject: 'index.html', priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      defaultBehavior: {origin: origins.S3BucketOrigin.withOriginAccessControl(web),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: securityHeaders,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED},
      additionalBehaviors: {
        '/api/*': {origin: new origins.HttpOrigin(`${rest.restApiId}.execute-api.${this.region}.amazonaws.com`, {
          originPath: '/lab', readTimeout: Duration.seconds(60), connectionAttempts: 1,
        }), allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          responseHeadersPolicy: securityHeaders, compress: false},
        '/app-config.json': {origin: origins.S3BucketOrigin.withOriginAccessControl(web),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
          responseHeadersPolicy: securityHeaders, cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED},
      },
    });
    const webUrl = `https://${distribution.distributionDomainName}/`;
    const client = pool.addClient('Browser', {
      userPoolClientName: 'agentcore-chat-lab-browser', generateSecret: false,
      preventUserExistenceErrors: true, enableTokenRevocation: true,
      accessTokenValidity: Duration.minutes(15), idTokenValidity: Duration.minutes(15),
      refreshTokenValidity: Duration.hours(8),
      oAuth: {flows: {authorizationCodeGrant: true}, callbackUrls: [webUrl], logoutUrls: [webUrl],
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.resourceServer(resourceServer, invokeScope)]},
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
    });
    const clientResource = client.node.defaultChild as cognito.CfnUserPoolClient;
    clientResource.addPropertyOverride('ExplicitAuthFlows', ['ALLOW_USER_SRP_AUTH']);
    new ssm.StringParameter(this, 'Configuration', {
      parameterName: PARAMETER,
      stringValue: Stack.of(this).toJsonString({modelId: settings.modelId, maxTokens: 1024,
        splunkProject: 'agentcore-chat-lab', splunkAgentStream: 'chat', captureContent: true,
        splunkControlEnabled: true,
        cognitoClientId: client.userPoolClientId}),
      description: 'Non-secret chat model, telemetry destination, and expected browser client',
    });
    new cognito.CfnUserPoolUser(this, 'InitialUser', {
      userPoolId: pool.userPoolId, username: settings.initialEmail,
      desiredDeliveryMediums: ['EMAIL'], userAttributes: [{name: 'email', value: settings.initialEmail}],
    });
    new budgets.CfnBudget(this, 'Budget', {
      budget: {budgetName: 'AgentCoreChatLab-Account-25USD', budgetType: 'COST', timeUnit: 'MONTHLY',
        budgetLimit: {amount: settings.monthlyBudgetUsd, unit: 'USD'}},
      notificationsWithSubscribers: [50, 100].map(threshold => ({
        notification: {notificationType: 'ACTUAL', comparisonOperator: 'GREATER_THAN', threshold, thresholdType: 'PERCENTAGE'},
        subscribers: [{subscriptionType: 'EMAIL', address: settings.initialEmail}],
      })),
    });
    new cloudwatch.Alarm(this, 'ApiErrors', {metric: adapter.metricErrors({period: Duration.minutes(5)}),
      threshold: 3, evaluationPeriods: 1, treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING});
    for (const [name, value] of Object.entries({
      WebUrl: webUrl, WebBucket: web.bucketName, DistributionId: distribution.distributionId,
      ApiUrl: rest.url, UserPoolId: pool.userPoolId, ClientId: client.userPoolClientId,
      AuthDomain: `https://${domain.domainName}.auth.${this.region}.amazoncognito.com`,
      RuntimeId: runtime.attrAgentRuntimeId, RuntimeArn: runtime.attrAgentRuntimeArn,
      RuntimeRoleArn: runtimeRole.roleArn, ConfigParameter: PARAMETER,
      LogKeyArn: logKey.keyArn, CiscoSecretArn: ciscoArn, SplunkSecretArn: splunkArn,
    })) new CfnOutput(this, name, {value});
  }
}
