# -*- coding: utf-8 -*-
"""
    flaskext.oauth
    ~~~~~~~~~~~~~~

    Description of the module goes here...

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import httplib2
from functools import wraps
from urlparse import urljoin
from flask import request, session, json, redirect
from werkzeug import url_decode, url_encode, url_quote, \
     parse_options_header, Headers
import oauth2


def parse_response(resp, content, strict=False):
    ct, options = parse_options_header(resp['content-type'])
    if ct == 'application/json':
        return json.loads(content)
    elif ct != 'application/x-www-form-urlencoded':
        if strict:
            return content
    return url_decode(content).to_dict()


def encode_request_data(data, format):
    if format is None:
        return data, None
    elif format == 'json':
        return json.dumps(data), 'application/json'
    elif format == 'urlencoded':
        return url_encode(data), 'application/x-www-form-urlencoded'
    raise TypeError('Unknown format %r' % format)


class OAuthResponse(object):

    def __init__(self, resp, content):
        self.headers = Headers(resp)
        self.raw_data = content
        self.data = parse_response(resp, content, strict=True)

    @property
    def status(self):
        return self.headers.get('status', type=int)


class OAuthClient(oauth2.Client):

    def request_new_token(self, uri, callback=None):
        params = {}
        if callback is not None:
            params['oauth_callback'] = callback
        req = oauth2.Request.from_consumer_and_token(
            self.consumer, token=self.token,
            http_method='POST', http_url=uri, parameters=params)
        req.sign_request(self.method, self.consumer, self.token)
        body = req.to_postdata()
        headers = {
            'Content-Type':     'application/x-www-form-urlencoded',
            'Content-Length':   str(len(body))
        }
        return httplib2.Http.request(self, uri, method='POST',
                                     body=body, headers=headers)


class OAuthException(RuntimeError):
    pass


class OAuth(object):

    def remote_app(self, name, **kwargs):
        return OAuthRemoteApp(self, name, **kwargs)


class OAuthRemoteApp(object):

    def __init__(self, oauth, name, request_token_url,
                 access_token_url, authorize_url,
                 consumer_key, consumer_secret,
                 base_url=None, free_token_after_auth=True):
        self.oauth = oauth
        self.base_url = base_url
        self.name = name
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.tokengetter_func = None
        self.free_token_after_auth = free_token_after_auth

        self._consumer = oauth2.Consumer(self.consumer_key,
                                         self.consumer_secret)
        self._client = OAuthClient(self._consumer)

    def get(self, *args, **kwargs):
        kwargs['method'] = 'GET'
        return self.request(*args, **kwargs)

    def post(self, *args, **kwargs):
        kwargs['method'] = 'POST'
        return self.request(*args, **kwargs)

    def put(self, *args, **kwargs):
        kwargs['method'] = 'PUT'
        return self.request(*args, **kwargs)

    def delete(self, *args, **kwargs):
        kwargs['method'] = 'DELETE'
        return self.request(*args, **kwargs)

    def make_client(self):
        return oauth2.Client(self._consumer, self.get_request_token())

    def request(self, url, data=None, headers=None, format='urlencoded',
                method='GET', content_type=None):
        if headers is None:
            headers = {}
        client = self.make_client()
        if content_type is None:
            data, content_type = encode_request_data(data, format)
        if content_type is not None:
            headers['Content-Type'] = content_type
        resp, content = client.request(self.expand_url(url), method=method,
                                       body=data, headers=headers)
        return OAuthResponse(resp, content)

    def expand_url(self, url):
        return urljoin(self.base_url, url)

    def generate_request_token(self, callback=None):
        if callback is not None:
            callback = urljoin(request.url, callback)
        resp, content = self._client.request_new_token(
            self.expand_url(self.request_token_url), callback)
        if resp['status'] != '200':
            raise OAuthException('Failed to generate request token')
        data = parse_response(resp, content)
        if data is None:
            raise OAuthException('Invalid token response from ' + self.name)
        tup = (data['oauth_token'], data['oauth_token_secret'])
        session[self.name + '_oauthtok'] = tup
        return tup

    def get_request_token(self):
        rv = self.tokengetter_func()
        if rv is None:
            rv = session.get(self.name + '_oauthtok')
            if rv is None:
                raise OAuthException('No token available')
        return oauth2.Token(*rv)

    def free_request_token(self):
        session.pop(self.name + '_oauthtok')

    def authorize(self, callback=None):
        token = self.generate_request_token(callback)[0]
        url = '%s?oauth_token=%s' % (self.expand_url(self.authorize_url),
                                     url_quote(token))
        return redirect(url)

    def tokengetter(self, f):
        self.tokengetter_func = f
        return f

    def authorized_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client = self.make_client()
            resp, content = client.request('%s?oauth_verifier=%s' % (
                self.expand_url(self.access_token_url),
                request.args['oauth_verifier']
            ), 'GET')
            if resp['status'] != '200':
                raise OAuthException('Invalid response from ' + self.name)
            data = parse_response(resp, content)
            try:
                return f(data)
            finally:
                if self.free_token_after_auth:
                    self.free_request_token()
        return decorated
