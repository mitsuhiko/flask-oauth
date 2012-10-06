Flask-OAuth
===========

.. module:: flask_oauth

Flask-OAuth is an extension to `Flask`_ that allows you to interact with
remote `OAuth`_ enabled applications.  Currently it only implements the
consumer interface so you cannot expose your own API with OAuth.

Flak-OAuth depends on the `python-oauth2`_ module.

Features
--------

- Support for OAuth 1.0a
- Friendly API
- Direct integration with Flask
- Basic support for remote method invocation of RESTful APIs

Installation
------------

Install the extension with one of the following commands::

    $ pip install Flask-OAuth

Alternatively, use `easy_install`::

    $ easy_install Flask-OAuth

.. _Flask: http://flask.pocoo.org/
.. _OAuth: http://oauth.net/
.. _python-oauth2: http://pypi.python.org/pypi/oauth2/

Defining Remote Applications
----------------------------

To connect to a remote application create a :class:`OAuth`
object and register a remote application on it using
the :meth:`~OAuth.remote_app` method::

    from flask_oauth import OAuth

    oauth = OAuth()
    the_remote_app = oauth.remote_app('the remote app',
        ...
    )

A remote application must define several URLs required by the
OAuth machinery:

- `request_token_url`
- `access_token_url`
- `authorize_url` 

Additionally the application should define an issued `consumer_key`
and `consumer_secret`.

You can find these values by registering your application with the remote
application you want to connect with.

Additionally you can provide a `base_url` that is prefixed to *all*
relative URLs used in the remote app.

For Twitter the setup would look like this::

    twitter = oauth.remote_app('twitter',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authenticate',
        consumer_key='<your key here>',
        consumer_secret='<your secret here>'
    )

Now that the application is created one can start using the OAuth system.
One thing is missing: the tokengetter. OAuth uses a token and a secret to
figure out who is connecting to the remote application.  After
authentication/authorization this information is passed to a function on
your side and it is your responsibility to remember it.

The following rules apply:

-   It's your responsibility to store that information somewhere
-   That information lives for as long as the user did not revoke the
    access for your application on the remote application.  If it was
    revoked and the user re-enabled the application you will get different
    keys, so if you store them in the database don't forget to check if
    they changed in the authorization callback.
-   During the authorization handshake a temporary token and secret are
    issued. Your tokengetter is not used during that period.

For a simple test application, storing that information in the session is
probably sufficient::

    from flask import session

    @twitter.tokengetter
    def get_twitter_token(token=None):
        return session.get('twitter_token')

If the token does not exist, the function must return `None`, and
otherwise return a tuple in the form ``(token, secret)``.  The function
might also be passed a `token` parameter.  This is user defined and can be
used to indicate another token.  Imagine for instance you want to support
user and application tokens or different tokens for the same user.

The name of the token can be passed to to the
:meth:`~OAuthRemoteApp.request` function.

Signing in / Authorizing
------------------------

To sign in with Twitter or link a user account with a remote
Twitter user, simply call into
:meth:`~OAuthRemoteApp.authorize` and pass it the URL that the user should be
redirected back to. For example:: 

    @app.route('/login')
    def login():
        return twitter.authorize(callback=url_for('oauth_authorized',
            next=request.args.get('next') or request.referrer or None))

If the application redirects back, the remote application will have passed all
relevant information to the `oauth_authorized` function: a special
response object with all the data, or ``None`` if the user denied the
request.  This function must be decorated as
:meth:`~OAuthRemoteApp.authorized_handler`::

    from flask import redirect

    @app.route('/oauth-authorized')
    @twitter.authorized_handler
    def oauth_authorized(resp):
        next_url = request.args.get('next') or url_for('index')
        if resp is None:
            flash(u'You denied the request to sign in.')
            return redirect(next_url)

        session['twitter_token'] = (
            resp['oauth_token'],
            resp['oauth_token_secret']
        )
        session['twitter_user'] = resp['screen_name']

        flash('You were signed in as %s' % resp['screen_name'])
        return redirect(next_url)

We store the token and the associated secret in the session so that the
tokengetter can return it.  Additionally we also store the Twitter username
that was sent back to us so that we can later display it to the user.  In
larger applications it is recommended to store satellite information in a
database instead to ease debugging and more easily handle additional information
associated with the user.

Facebook OAuth
--------------

For Facebook the flow is very similar to Twitter or other OAuth systems
but there is a small difference.  You're not using the `request_token_url`
at all and you need to provide a scope in the `request_token_params`::

    facebook = oauth.remote_app('facebook',
        base_url='https://graph.facebook.com/',
        request_token_url=None,
        access_token_url='/oauth/access_token',
        authorize_url='https://www.facebook.com/dialog/oauth',
        consumer_key=FACEBOOK_APP_ID,
        consumer_secret=FACEBOOK_APP_SECRET,
        request_token_params={'scope': 'email'}
    )

Furthermore the `callback` is mandatory for the call to
:meth:`~OAuthRemoteApp.authorize` and has to match the base URL that was
specified in the Facebook application control panel.  For development you
can set it to ``localhost:5000``.

The `APP_ID` and `APP_SECRET` can be retrieved from the Facebook app
control panel.  If you don't have an application registered yet you can do
this at `facebook.com/developers <https://www.facebook.com/developers/createapp.php>`_.

Invoking Remote Methods
-----------------------

Now the user is signed in, but you probably want to use
OAuth to call protected remote API methods and not just sign in.  For
that, the remote application object provides a
:meth:`~OAuthRemoteApp.request` method that can request information from
an OAuth protected resource.  Additionally there are shortcuts like
:meth:`~OAuthRemoteApp.get` or :meth:`~OAuthRemoteApp.post` to request
data with a certain HTTP method.

For example to create a new tweet you would call into the Twitter
application as follows::

    resp = twitter.post('statuses/update.json', data={
        'status':   'The text we want to tweet'
    })
    if resp.status == 403:
        flash('Your tweet was too long.')
    else:
        flash('Successfully tweeted your tweet (ID: #%s)' % resp.data['id'])

Or to display the users' feed we can do something like this::

    resp = twitter.get('statuses/home_timeline.json')
    if resp.status == 200:
        tweets = resp.data
    else:
        tweets = None
        flash('Unable to load tweets from Twitter. Maybe out of '
              'API calls or Twitter is overloaded.')

Flask-OAuth will do its best to send data encoded in the right format to
the server and to decode it when it comes back.  Incoming data is encoded
based on the `mimetype` the server sent and is stored in the
:attr:`~OAuthResponse.data` attribute.  For outgoing data a default of
``'urlencode'`` is assumed. When a different format is needed, one can
specify it with the `format` parameter.  The following formats are
supported:

**Outgoing**:
    - ``'urlencode'`` - form encoded data (`GET` as URL and `POST`/`PUT` as
      request body)
    - ``'json'`` - JSON encoded data (`POST`/`PUT` as request body)

**Incoming**
    - ``'urlencode'`` - stored as flat unicode dictionary
    - ``'json'`` - decoded with JSON rules, most likely a dictionary
    - ``'xml'`` - stored as elementtree element

Unknown incoming data is stored as a string.  If outgoing data of a different
format is needed, `content_type` should be specified instead and the
data provided should be an encoded string.

API Reference
-------------

.. autoclass:: OAuth
   :members:

.. autoclass:: OAuthRemoteApp
   :members:

.. autoclass:: OAuthResponse
   :members:

.. autoexception:: OAuthException
   :members:
