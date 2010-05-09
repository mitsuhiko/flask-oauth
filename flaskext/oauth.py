# -*- coding: utf-8 -*-
"""
    flaskext.oauth
    ~~~~~~~~~~~~~~

    Implements basic OAuth support for Flask.

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


_etree = None
def get_etree():
    """Return an elementtree implementation.  Prefers lxml"""
    global _etree
    if _etree is None:
        try:
            from lxml import etree as _etree
        except ImportError:
            try:
                from xml.etree import cElementTree as _etree
            except ImportError:
                try:
                    from xml.etree import ElementTree as _etree
                except ImportError:
                    raise TypeError('lxml or etree not found')
    return _etree


def parse_response(resp, content, strict=False):
    ct, options = parse_options_header(resp['content-type'])
    if ct == 'application/json':
        return json.loads(content)
    elif ct in ('application/xml', 'text/xml'):
        # technically, text/xml is ascii based but because many
        # implementations get that wrong and utf-8 is a superst
        # of utf-8 anyways, there is not much harm in assuming
        # utf-8 here
        charset = options.get('charset', 'utf-8')
        return get_etree().fromstring(content.decode(charset))
    elif ct != 'application/x-www-form-urlencoded':
        if strict:
            return content
    charset = options.get('charset', 'utf-8')
    return url_decode(content, charset=charset).to_dict()


def add_query(url, args):
    if not args:
        return url
    return url + ('?' in url and '&' or '?') + url_encode(args)


def encode_request_data(data, format):
    if format is None:
        return data, None
    elif format == 'json':
        return json.dumps(data), 'application/json'
    elif format == 'urlencoded':
        return url_encode(data), 'application/x-www-form-urlencoded'
    raise TypeError('Unknown format %r' % format)


class OAuthResponse(object):
    """Contains the response sent back from an OAuth protected remote
    application.
    """

    def __init__(self, resp, content):
        #: a :class:`~werkzeug.Headers` object with the response headers
        #: the application sent.
        self.headers = Headers(resp)
        #: the raw, unencoded content from the server
        self.raw_data = content
        #: the parsed content from the server
        self.data = parse_response(resp, content, strict=True)

    @property
    def status(self):
        """The status code of the response."""
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
    """Registry for remote applications.  In the future this will also
    be the central class for OAuth provider functionality.
    """

    def __init__(self):
        self.remote_apps = {}

    def remote_app(self, name, register=True, **kwargs):
        """Registers a new remote applicaton.  If `param` register is
        set to `False` the application is not registered in the
        :attr:`remote_apps` dictionary.  The keyword arguments are
        forwarded to the :class:`OAuthRemoteApp` consturctor.
        """
        app = OAuthRemoteApp(self, name, **kwargs)
        if register:
            assert name not in self.remote_apps, \
                'application already registered'
            self.remote_apps[name] = app
        return app


class OAuthRemoteApp(object):
    """Represents a remote application.

    :param oauth: the associated :class:`OAuth` object.
    :param name: then name of the remote application
    :param request_token_url: the URL for requesting new tokens
    :param access_token_url: the URL for token exchange
    :param authorize_url: the URL for authorization
    :param consumer_key: the application specific consumer key
    :param consumer_secret: the application specific consumer secret
    """

    def __init__(self, oauth, name, base_url,
                 request_token_url,
                 access_token_url, authorize_url,
                 consumer_key, consumer_secret):
        self.oauth = oauth
        #: the `base_url` all URLs are joined with.
        self.base_url = base_url
        self.name = name
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorize_url = authorize_url
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.tokengetter_func = None

        self._consumer = oauth2.Consumer(self.consumer_key,
                                         self.consumer_secret)
        self._client = OAuthClient(self._consumer)

    def get(self, *args, **kwargs):
        """Sends a ``GET`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'GET'
        return self.request(*args, **kwargs)

    def post(self, *args, **kwargs):
        """Sends a ``POST`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'POST'
        return self.request(*args, **kwargs)

    def put(self, *args, **kwargs):
        """Sends a ``PUT`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'PUT'
        return self.request(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Sends a ``DELETE`` request.  Accepts the same parameters as
        :meth:`request`.
        """
        kwargs['method'] = 'DELETE'
        return self.request(*args, **kwargs)

    def make_client(self):
        """Creates a new `oauth2` Client object with the token attached.
        Usually you don't have to do that but use the :meth:`request`
        method instead.
        """
        return oauth2.Client(self._consumer, self.get_request_token())

    def request(self, url, data=None, headers=None, format='urlencoded',
                method='GET', content_type=None):
        """Sends a request to the remote server with OAuth tokens attached.
        The `url` is joined with :attr:`base_url` if the URL is relative.

        :param url: where to send the request to
        :param data: the data to be sent to the server.  If the request method
                     is ``GET`` the data is appended to the URL as query
                     parameters, otherwise encoded to `format` if the format
                     is given.  If a `content_type` is provided instead, the
                     data must be a string encoded for the given content
                     type and used as request body.
        :param headers: an optional dictionary of headers.
        :param format: the format for the `data`.  Can be `urlencoded` for
                       URL encoded data or `json` for JSON.
        :param method: the HTTP request method to use.
        :param content_type: an optional content type.  If a content type is
                             provided, the data is passed as it and the
                             `format` parameter is ignored.
        :return: an :class:`OAuthResponse` object.
        """
        headers = dict(headers or {})
        client = self.make_client()
        url = self.expand_url(url)
        if method == 'GET':
            assert format == 'urlencoded'
            if data is not None:
                url = add_query(url, data)
                data = None
        else:
            if content_type is None:
                data, content_type = encode_request_data(data, format)
            if content_type is not None:
                headers['Content-Type'] = content_type
                headers['Content-Length'] = str(len(data))
        return OAuthResponse(*client.request(url, method=method,
                                             body=data, headers=headers))

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
        assert self.tokengetter_func is not None, 'missing tokengetter function'
        rv = self.tokengetter_func()
        if rv is None:
            rv = session.get(self.name + '_oauthtok')
            if rv is None:
                raise OAuthException('No token available')
        return oauth2.Token(*rv)

    def free_request_token(self):
        session.pop(self.name + '_oauthtok')

    def authorize(self, callback=None):
        """Returns a redirect response to the remote authorization URL with
        the signed callback given.  The callback must be `None` in which
        case the application will most likely switch to PIN based authentication
        or use a remotely stored callback URL.  Alternatively it's an URL
        on the system that has to be decorated as :meth:`authorized_handler`.
        """
        token = self.generate_request_token(callback)[0]
        url = '%s?oauth_token=%s' % (self.expand_url(self.authorize_url),
                                     url_quote(token))
        return redirect(url)

    def tokengetter(self, f):
        """Registers a function as tokengetter.  The tokengetter has to return
        a tuple of ``(token, secret)`` with the user's token and token secret.
        If the data is unavailable, the function must return `None`.
        """
        self.tokengetter_func = f
        return f

    def authorized_handler(self, f):
        """Injects additional authorization functionality into the function.
        The function will be passed the response object as first argument
        if the request was allowed, or `None` if access was denied.  When the
        authorized handler is called, the temporary issued tokens are already
        destroyed.
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'oauth_verifier' in request.args:
                client = self.make_client()
                resp, content = client.request('%s?oauth_verifier=%s' % (
                    self.expand_url(self.access_token_url),
                    request.args['oauth_verifier']
                ), 'GET')
                if resp['status'] != '200':
                    raise OAuthException('Invalid response from ' + self.name)
                data = parse_response(resp, content)
            else:
                data = None
            self.free_request_token()
            return f(*((data,) + args), **kwargs)
        return decorated
