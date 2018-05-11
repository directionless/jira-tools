#!/usr/bin/env python
# Example code to using jira-tools auth

import argparse
import logging
import os
import sys

# Yeah... This isn't a real module yet
sys.path.insert(0, "../settings")
from jiratools import JiraTools


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


def main():
    args = parse_args()
    jt = JiraTools(config_file=args.config, auth_file=args.auth, url=args.url)
    j = jt.jira()

    for issue in args.tickets:
        print("\nFetching %s" % issue)
        issue = j.issue(issue)
        print(issue.fields.summary)


if __name__ == "__main__":
    logger = logging.getLogger('Get Ticket Example')
    logging.basicConfig()
    main()
