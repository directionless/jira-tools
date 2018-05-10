# Jira Oauth Dance

Inspired by an ex-employer, a set of examples to talk to jira.

While this code will probably work, it should be considered PoC code. 

## Config Files

It uses a json config file in `/etc/jira-tools.json` to store the
shared jira credentials. This allows the shared credentials to be
managed by existing host management tools.

See [jira-tools.json](./jira-tools.json) for an example

## Setup Secrets

You'll need a made up secret, and an RSA key. These will be used to
authenticate the application (this script) to the jira server. The are
insufficient for authorization, and inherently need to be shared with
all users of this application.

```
openssl rand -base64 32 -out shared-secret.txt

openssl genrsa -out jira.key 2048
openssl rsa -pubout -in jira.key -out jira.crt

make-json.py | jq . > jira-tools.json
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
python jira-oauth-dance.py
cat ~/.jira-credentials.json
python get-ticket.py TIK-1 TIK-2

```

## A note about oauth

There are many flavors of oauth. As of 2018-Q1, I think jira only
supports oauth1. Not oauth2. Not OIDC. This you might need to find older
libraries or examples for how to make it go. 

## ToDo

Some things that would make this more production oriented.

* Port to golang, Distributing python code is hard
* Don't write secrets to disk, use the keychain
* Figure out how to renew credentials, and not just issue new ones

## References

https://developer.atlassian.com/server/jira/platform/oauth/
