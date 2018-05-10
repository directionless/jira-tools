#!/usr/bin/env python

# really quick formatting hack

import json

config = {
    "metadata": {
        "default": "https://jira.example.com"
    },
    "https://jira.example.com": {
        "consumer_key": open('shared-secret.txt','r').read().rstrip(),
        "rsa_key": open('jira.key','r').read().rstrip(),
        "rsa_cert": open('jira.crt','r').read().rstrip(),
    }
}

print(json.dumps(config))
