"""Prompt locally for SDK credentials; store them only in app-specific Secrets Manager entries."""
import argparse
import getpass
import json
import re
from urllib.parse import urlsplit

import boto3


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', choices=['cisco', 'splunk', 'both'], default='both')
    parser.add_argument('--profile', default='aidefense')
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--cisco-origin', default='https://us.api.inspect.aidefense.security.cisco.com')
    parser.add_argument('--splunk-realm', default='us1')
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if session.client('sts').get_caller_identity()['Account'] != '774569412819':
        raise ValueError('Wrong AWS account; expected 774569412819')
    client = session.client('secretsmanager')
    print('Credentials entered here are sent to AWS Secrets Manager in account 774569412819, us-east-1.')
    print('They are not printed or saved locally. This command does not contact Cisco or Splunk.')
    if args.service in ['cisco', 'both']:
        parsed = urlsplit(args.cisco_origin)
        if parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.aidefense.security.cisco.com') or parsed.path not in ['', '/'] or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError('Use a Cisco HTTPS inspection API origin without a route or query')
        key = getpass.getpass('Separate Cisco inspection API key (empty to skip): ')
        if key:
            policy = input('Optional Cisco policy ID (empty for tenant default): ').strip()
            value = {'api_key': key, 'inspection_origin': args.cisco_origin.rstrip('/')}
            if policy:
                value['policy_id'] = policy
            client.put_secret_value(SecretId='/agentcore-chat-lab/cisco', SecretString=json.dumps(value))
            print('Stored /agentcore-chat-lab/cisco')
    if args.service in ['splunk', 'both']:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', args.splunk_realm):
            raise ValueError('Invalid Splunk realm')
        token = getpass.getpass('Splunk Observability Cloud ingest token (empty to skip): ')
        if token:
            client.put_secret_value(SecretId='/agentcore-chat-lab/splunk',
                                    SecretString=json.dumps({'realm': args.splunk_realm, 'o11y_token': token}))
            print('Stored /agentcore-chat-lab/splunk')


if __name__ == '__main__':
    main()
