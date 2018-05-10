#!/usr/bin/env python
# Example code to using jira-tools auth

import argparse
import jira
import json
import logging
import os
import sys


def parse_args():
    parser = argparse.ArgumentParser(description='Fetch Ticket Info')

    parser.add_argument('tickets', nargs='*',
                        help='List of tickets to fetch info for')

    parser.add_argument('-c', '--config', dest='config', default='/etc/jira-tools.json',
                        help='Config file for jira tools. Includes the secrets')

    parser.add_argument('-j', '--jira', dest='url', required=False,
                        help='Jira URL')

    parser.add_argument('-a', '--auth-file', dest='auth', default='~/.jira-credentials.json',
                        help='Location for the auth file')
    args = parser.parse_args()
    return args


def get_jira_url(args):
    config_data = json.loads(open(args.config, 'r').read())

    url = config_data.get('metadata', {}).get('default', None)

    if args.url is not None:
        url = args.url

    if url is None:
        logging.critical('No specified jira url. Either put it in the config, or use --jira')
        sys.exit(1)

    return url


def setup_jira(url, args):
    config_data = json.loads(open(os.path.expanduser(args.config), 'r').read())
    auth_data = json.loads(open(os.path.expanduser(args.auth), 'r').read())

    merged_creds = {
        'access_token': auth_data[url]['oauth_token'],
        'access_token_secret': auth_data[url]['oauth_token_secret'],
        'consumer_key': config_data[url]['consumer_key'],
        'key_cert': config_data[url]['rsa_key'],
    }

    j = jira.JIRA(url,
                  validate=True,
                  get_server_info=True,
                  timeout=5,
                  oauth=merged_creds)

    return j


def main():
    args = parse_args()
    url = get_jira_url(args)
    j = setup_jira(url, args)

    for issue in args.tickets:
        print("\nFetching %s" % issue)
        issue = j.issue(issue)
        print(issue.fields.summary)


if __name__ == "__main__":
    logger = logging.getLogger('Get Ticket Example')
    logging.basicConfig()
    main()
