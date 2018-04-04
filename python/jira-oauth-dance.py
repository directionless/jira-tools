#!/usr/bin/env python

# Crypto...
# A note on requests_oauthlib.oauth1_session.SIGNATURE_RSA,
# oauthlib.oauth1.SIGNATURE_RSA,

import argparse
import jira
import json
import logging
# import oauthlib
import os
import requests
import requests_oauthlib
import time
import urllib
import webbrowser


def parse_args():
    parser = argparse.ArgumentParser(description='Exchanges web sessions for oauth tokens')

    parser.add_argument('-j', '--jira', dest='url', required=True,
                        help='Jira URL')

    parser.add_argument('-s', '--secret', dest='consumer_key', required=True,
                        help='Consumer Secret Key (Application Secret Shared with Jira)')

    parser.add_argument('-k', '--rsa-key', dest='rsa_key', required=True,
                        type=argparse.FileType('r'),
                        help='Consumer RSA Key (Application Secret Shared with Jira)')

    parser.add_argument('-o', '--output', dest='out', default='credentials.json',
                        type=argparse.FileType('w'),
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
    args.rsa_key = args.rsa_key.read()
    return args


def get_initial_oauth(args):

    oauth = requests_oauthlib.OAuth1(
        args.consumer_key,
        signature_method=requests_oauthlib.oauth1_session.SIGNATURE_RSA,
        rsa_key=args.rsa_key)

    res = requests.post(args.url + '/plugins/servlet/oauth/request-token',
                        auth=oauth)
    res.raise_for_status()

    data = dict(urllib.parse.parse_qsl(res.content))

    return data


def get_authentication(args, oauth_data):

    oauth = requests_oauthlib.OAuth1(
        args.consumer_key,
        signature_method=requests_oauthlib.oauth1_session.SIGNATURE_RSA,
        rsa_key=args.rsa_key,
        resource_owner_key=oauth_data[b'oauth_token'],
        resource_owner_secret=oauth_data[b'oauth_token_secret'])

    jira_attempts = 0
    while(True):
        time.sleep(args.poll_interval)
        jira_attempts += 1

        res = requests.post(args.url + '/plugins/servlet/oauth/access-token', auth=oauth)
        if res.status_code == 200:
            break

        if args.poll_interval * jira_attempts > args.jira_timeout:
            logger.critical('Timed out')
            os.exit(1)

    data = dict(urllib.parse.parse_qsl(res.content))

    # Field names are what the jira python lib expects
    credentials = {
        'access_token': data[b'oauth_token'].decode('utf-8'),
        'access_token_secret': data[b'oauth_token_secret'].decode('utf-8'),
        'consumer_key': args.consumer_key,
        'key_cert': args.rsa_key
    }
    return credentials


def test_creds(url, credentials):
    # We don't need an api call, this will fail if the creds are invalid
    jira.JIRA(url,
              validate=True,
              get_server_info=True,
              timeout=5,
              oauth=credentials)


def main():
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level))

    oauth_data = get_initial_oauth(args)
    authorize_url = "{jira}/plugins/servlet/oauth/authorize?oauth_token={token}".format(
        jira=args.url, token=oauth_data[b'oauth_token'].decode('utf-8')
    )

    print('Please authenticate this application to Jira.')
    print('You can open the following URL, this script may do it for you')
    print(authorize_url)
    if args.no_web is False:
        webbrowser.open_new(authorize_url)

    credentials = get_authentication(args, oauth_data)

    test_creds(args.url, credentials)

    # print(json.dumps(credentials, indent=4, sort_keys=True))
    json.dump(credentials, args.out, indent=4, sort_keys=True)


if __name__ == "__main__":
    logger = logging.getLogger('jira-oauth-dance')
    logging.basicConfig()
    main()
