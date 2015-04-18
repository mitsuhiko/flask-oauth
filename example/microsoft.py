from flask import Flask, redirect, url_for, session
from flask_oauth import OAuth


MICROSOFT_CLIENT_ID = 'CLIENT_ID'
MICROSOFT_CLIENT_SECRET = 'CLIENT_SECRET'
REDIRECT_URI = '/microsoft_callback' 

SECRET_KEY = 'development key'
DEBUG = True

app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

microsoft = oauth.remote_app('microsoft',
    base_url='https://login.live.com',
    authorize_url='https://login.live.com/oauth20_authorize.srf',
    request_token_url=None,
    request_token_params={'scope': 'wl.signin wl.emails',
                          'response_type': 'code'},
    access_token_url='https://login.live.com/oauth20_token.srf',
    access_token_method='POST',
    access_token_params={'grant_type': 'authorization_code'},
    consumer_key=MICROSOFT_CLIENT_ID,
    consumer_secret=MICROSOFT_CLIENT_SECRET)

@app.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    # headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://apis.live.net/v5.0/me?access_token=%s' % access_token)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()

    return res.read()


@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return microsoft.authorize(callback=callback)



@app.route(REDIRECT_URI)
@microsoft.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    print "access_token:", access_token
    session['access_token'] = access_token, ''
    return redirect(url_for('index'))


@microsoft.tokengetter
def get_access_token():
    return session.get('access_token')


def main():
    app.run()


if __name__ == '__main__':
    main()


