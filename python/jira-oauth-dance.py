#!/usr/bin/env python

# Crypto...
# A note on requests_oauthlib.oauth1_session.SIGNATURE_RSA,
# oauthlib.oauth1.SIGNATURE_RSA,

import argparse
import jira
import json
import logging
import os
import requests
import requests_oauthlib
import time
import urllib
import webbrowser
import sys

# Yeah... This isn't a real module yet
sys.path.insert(0, "../settings")
from jiratools import JiraTools


def parse_args():
    parser = argparse.ArgumentParser(description='Exchanges web sessions for oauth tokens')

    parser.add_argument('-c', '--config', dest='config', default='/etc/jira-tools.json',
                        help='Config file for jira tools. Includes the secrets')

    parser.add_argument('-j', '--jira', dest='url', required=False,
                        help='Jira URL')

    parser.add_argument('-o', '--output', dest='outfile', default='~/.jira-credentials.json',
                        help='Where to output credentials')

    parser.add_argument('--no-webbrowser', dest='no_web', action='store_true',
                        default=False,
                        help='Skip opening in a web browser')

    parser.add_argument('--timeout', dest='jira_timeout', default=120,
                        help='How long to wait for the user to accept the auth request')

    parser.add_argument('--poll-interval', dest='poll_interval', default=2,
                        help='How often to poll jira for auth acceptance')

    parser.add_argument('--log-level', dest='log_level', default='ERROR',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")

    args = parser.parse_args()
    return args


def get_initial_oauth(url, auth):
    oauth = requests_oauthlib.OAuth1(
        auth['consumer_key'],
        signature_method=requests_oauthlib.oauth1_session.SIGNATURE_RSA,
        rsa_key=auth['rsa_key'])

    res = requests.post(url + '/plugins/servlet/oauth/request-token',
                        auth=oauth)
    res.raise_for_status()

    data = dict(urllib.parse.parse_qsl(res.content))

    return data


def get_authentication(url, auth, oauth_data, timeout=10, poll_interval=2):
    oauth = requests_oauthlib.OAuth1(
        auth['consumer_key'],
        signature_method=requests_oauthlib.oauth1_session.SIGNATURE_RSA,
        rsa_key=auth['rsa_key'],
        resource_owner_key=oauth_data[b'oauth_token'],
        resource_owner_secret=oauth_data[b'oauth_token_secret'])

    jira_attempts = 0
    while(True):
        time.sleep(poll_interval)
        jira_attempts += 1

        res = requests.post(url + '/plugins/servlet/oauth/access-token', auth=oauth)
        if res.status_code == 200:
            break

        if poll_interval * jira_attempts > timeout:
            logger.critical('Timed out')
            sys.exit(1)

    data = dict(urllib.parse.parse_qsl(res.content))

    # python3 returns stuff as b'xxx' style strings, which breaks
    # other things. So squash it.
    decoded_data = {key.decode(): val.decode() for key, val in data.items()}

    return decoded_data


def test_creds(url, credentials):
    # We don't need an api call, this will fail if the creds are invalid
    jira.JIRA(url,
              validate=True,
              get_server_info=True,
              timeout=5,
              oauth=credentials)


def merge_credentials(shared_creds, session_creds):
    merged_creds = {
        'access_token': session_creds['oauth_token'],
        'access_token_secret': session_creds['oauth_token_secret'],
        'consumer_key': shared_creds['consumer_key'],
        'key_cert': shared_creds['rsa_key'],
    }
    return merged_creds


def main():
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level))

    # read in the config file, and figure out what's what
    config_data = json.loads(open(args.config, 'r').read())

    # Find the jira URL
    url = config_data.get('metadata', {}).get('default', None)
    if args.url is not None:
        url = args.url

    if url is None:
        logging.critical('No specified jira url. Either put it in the config, or use --jira')
        sys.exit(1)

    if url not in config_data:
        logging.critical('No jira config for "{url}"'.format(url=url))
        sys.exit(1)

    oauth_data = get_initial_oauth(url, config_data[url])

    authorize_url = "{jira}/plugins/servlet/oauth/authorize?oauth_token={token}".format(
        jira=url, token=oauth_data[b'oauth_token'].decode('utf-8')
    )

    print('Please authenticate this application to Jira.')
    print('You can open the following URL, this script may do it for you')
    print(authorize_url)
    if args.no_web is False:
        webbrowser.open_new(authorize_url)

    credentials = get_authentication(url, config_data[url], oauth_data, timeout=args.jira_timeout, poll_interval=args.poll_interval)

    merged_creds = merge_credentials(config_data[url], credentials)
    test_creds(url, merged_creds)

    # Some kinda ugly code to read file, ensure it's a dict, update
    # this jira server, and write it.
    credfile = os.path.expanduser(args.outfile)
    creddata = {
        '_meta': {}
        }
    if os.path.exists(credfile) and os.path.isfile(credfile):
        creddata = json.loads(open(credfile, 'r').read())

    creddata['_meta']['updated'] = time.strftime('%s')
    creddata['_meta']['created_by'] = 'Created by https://github.com/directionless/jira-tools'
    creddata[url] = credentials

    with open(credfile, 'w') as fh:
        json.dump(creddata, fh, indent=4, sort_keys=True)


if __name__ == "__main__":
    logger = logging.getLogger('jira-oauth-dance')
    logging.basicConfig()
    main()
