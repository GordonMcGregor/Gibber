#!/usr/bin/env python

import oauth2 as oauth
import time
import urllib

import urlparse

TOKEN_STORE = "/tmp/yammer.token"

#OAuth details for SENewsPosterBot
#Consumer (Application) Key
CONSUMER_KEY = ''

#Consumer (Application) Secret
CONSUMER_SECRET = ''

#Request Token URL
REQUEST_TOKEN_URL = 'https://www.yammer.com/oauth/request_token'

#Access Token URL
ACCESS_TOKEN_URL = 'https://www.yammer.com/oauth/access_token'

#Authorize URL
AUTH_URL = 'https://www.yammer.com/oauth/authorize'

authKey = ''
authSecret = ''

try:
    file_object = open(TOKEN_STORE)
    # read file details...
    lines = file_object.readlines( )
    file_object.close ()
    # parse...
    authKey = lines[0].rstrip('\n')
    authSecret = lines[1].rstrip('\n')
    print "access token : key : %s, secret : %s" % (authKey, authSecret)
except IOError:
    print 'Had problems reading file : ' + TOKEN_STORE


if (authKey == ''):
    consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
    client = oauth.Client(consumer)

    resp, content = client.request(REQUEST_TOKEN_URL, "GET")
    if resp['status'] != '200':
        raise Exception("Invalid response %s." % resp['status'])

    request_token = dict(urlparse.parse_qsl(content))

    print "Request Token:"
    print "oauth_token = %s" % request_token['oauth_token']
    print "oauth_token_secret = %s" % request_token['oauth_token_secret']
    print
    print "Go to the following link in your browser:"
    print "%s?oauth_token=%s" % (AUTH_URL, request_token['oauth_token'])
    print

    oauth_verifier = raw_input('What is the PIN? ')

    token = oauth.Token(request_token['oauth_token'], request_token['oauth_token_secret'])
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(ACCESS_TOKEN_URL, "POST")
    access_token = dict(urlparse.parse_qsl(content))

    print "Access Token:"
    print "access token = %s" % access_token['oauth_token']
    print "access secret = %s" % access_token['oauth_token_secret']
    print
    print "You may now access protected resources using the access tokens above." 
    print

    # store these items somewhere...
    toStore = access_token['oauth_token'] + "\n", access_token['oauth_token_secret'] + "\n"
    authKey = access_token['oauth_token']
    authSecret = access_token['oauth_token_secret']    
    file_object = open(TOKEN_STORE, 'w')
    file_object.writelines (toStore)
    file_object.close( )

# this can be either xml or json
url = 'https://www.yammer.com/api/v1/messages.xml'
#url = 'https://www.yammer.com/api/v1/users.xml'
#url = 'https://www.yammer.com/api/v1/groups.xml'


GROUP_ID = None
ME_ID = None

token = oauth.Token(key=authKey, secret=authSecret)
consumer = oauth.Consumer(key=CONSUMER_KEY, secret=CONSUMER_SECRET)

client = oauth.Client(consumer, token)
resp, content = client.request(url)

print resp
print content

# do something with the json...?

# sending messages to a group
url = 'https://www.yammer.com/api/v1/messages/'

params = {
    'group_id': GROUP_ID,
    'body' : 'Hello World',
#    'direct_to_id' : ME_ID
    'broadcast' : 1
}

encodedParams = urllib.urlencode (params)
if GROUP_ID or ME_ID:
    resp, content = client.request(url, 'POST', encodedParams)
    print resp['status']


