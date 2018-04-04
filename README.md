# Jira Oauth Dance

Inspired by an ex-employer, a set of examples to talk to jira.

## Setup Secrets

You'll need a made up secret, and an RSA key. These will be used to
authenticate the application (this script) to the jira server. The are
insufficient for authorization, and inherently need to be shared with
all users of this application.

```
openssl rand -base64 32 -out shared-secret.txt

openssl genrsa -out demo.key 2048
openssl rsa -pubout -in demo.key -out demo.crt
```

## Configure Jira

You'll need to configure a new application link in jira. This should
be found at https://<jira>/plugins/servlet/applinks/listApplicationLinks

Create New Link:
* URL: (The URL doesn't matter, and you can skip the error/warning by
clicking continue.

Link Applications:
* Application Name: Arbitary
* Application Type: Generic Application
* Create incoming link: checked.
* Leave all other options left blank.

Next Popup will be the incoming link:

* Consumer Key: Shared secret from earlier
* Consumer Name: Arbitrary
* Public Key: The RSA keypair previously generated
* Consumer Callback URL: https://YOUR_AUTH0_DOMAIN/login/callback


## Use

As a demo:

```
python jira-oauth-dance.py -j $jira \
  -s $(echo -n $(cat shared-secret.txt)) \
  -k demo.key

cat credentials.json

```

## A note about oauth

There are many flavors of oauth. As of 2018-Q1, I think jira only
supports oauth1. Not oauth2. Not OIDC. This you might need to find older
libraries or examples for how to make it go. 

## References

https://developer.atlassian.com/server/jira/platform/oauth/
