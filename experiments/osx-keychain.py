#!/usr/bin/env python

# Somewhat inspired by https://gist.github.com/gcollazo/9434580 but updated

import subprocess
import string
import random

def canonicalize(account=None, service=None):
    # We seem to need both an account and service, so if either is
    # None, just set them the same
    if account is None and service is None:
        raise ValueError('Need at least one of account or service')
    elif account is None:
        account = service
    elif service is None:
        service = account

    return(account, service)

def writesecret(account=None, service=None, secret=None):
    account, service = canonicalize(account, service)
    cmd = [
        '/usr/bin/security',
        'add-generic-password',
        '-U',
        '-s', service,
        '-a', account,
        '-w', secret
        ]
    subprocess.run(cmd)

def delsecret(account=None, service=None):
    account, service = canonicalize(account, service)
    cmd = [
        '/usr/bin/security',
        'delete-generic-password',
        '-s', service,
        '-a', account,
        ]
    subprocess.run(cmd, stdout=subprocess.PIPE)
    
def readsecret(account=None, service=None):
    account, service = canonicalize(account, service)
    cmd = [
        '/usr/bin/security',
        'find-generic-password',
        '-s', service,
        '-a', account,
        '-w'
        ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE)    
    secret = proc.stdout.rstrip().decode("utf-8")
    return(secret)


def main():
    chars = string.ascii_letters+string.digits
    secret = ''.join(random.choice(chars) for x in range(16))

    service = 'keychanin-test'
    account = 'keychain-test-account'
    
    print("Writing {sec} to service={ser} account={acc}".format(
        sec=secret, ser=service, acc=account))
    writesecret(account=account, service=service, secret=secret)

    read_sec = readsecret(account=account, service=service)
    print("Read {sec} back".format(sec=read_sec))

    if secret != read_sec:
        raise ValueError('no match')

    delsecret(account=account, service=service)
    
        
    
    
    
if __name__ == "__main__":
    main()
