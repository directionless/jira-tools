import jira
import json
import logging
import os
import sys

class JiraTools:
    '''Simple jira wrapper to facilitate auth'''
    config_data = {}
    auth_data = {}
    url = None

    def __init__(self, config_file=None, auth_file=None, url=None):
        self.config_data = self._read_file(config_file)
        self.auth_data = self._read_file(auth_file)
        self.url = self._get_jira_url(url)

    def jira(self):
        '''If the credentials are invalid, the jira connect call will fail. So this doubles as a test routine'''
        merged_creds = {}
        try:
            merged_creds['consumer_key'] = self.config_data[self.url]['consumer_key']
            merged_creds['key_cert'] = self.config_data[self.url]['rsa_key']
        except KeyError as err:
            logging.critical('Missing shared auth data\n')
            raise err

        try:
            merged_creds['access_token'] = self.auth_data[self.url]['oauth_token']
            merged_creds['access_token_secret'] = self.auth_data[self.url]['oauth_token_secret']
        except KeyError as err:
            logging.critical('Missing auth tokens. Do you need to oauth-dance?\n')
            raise err

        jira_obj = jira.JIRA(self.url,
                             validate=True,
                             get_server_info=True,
                             timeout=5,
                             oauth=merged_creds)

        return jira_obj

    def _get_jira_url(self, argsurl):
        url = self.config_data.get('metadata', {}).get('default', None)

        if argsurl is not None:
            url = argsurl

        if url is None:
            logging.critical('No specified jira url. Either put it in the config, or use --jira')
            sys.exit(1)

        return url

    def _read_file(self, filepath, default={}):
        if filepath is not None:
            filepath = os.path.expanduser(filepath)
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    default = json.load(f)
        return default

