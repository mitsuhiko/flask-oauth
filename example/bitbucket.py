from flask import Flask, redirect, url_for, session, request
from flask_oauth import OAuth


SECRET_KEY = 'development key'
DEBUG = True
BITBUCKET_CONSUMER_KEY = '<Consumer-Key>'
BITBUCKET_CONSUMER_SECRET = '<Consumer-Secret>'


app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

bitbucket = oauth.remote_app('bitbucket',
    base_url='https://api.bitbucket.org/1.0/',
    request_token_url='https://bitbucket.org/!api/1.0/oauth/request_token',
    access_token_url='https://bitbucket.org/!api/1.0/oauth/access_token',
    authorize_url='https://bitbucket.org/!api/1.0/oauth/authenticate',
    consumer_key=BITBUCKET_CONSUMER_KEY,
    consumer_secret=BITBUCKET_CONSUMER_SECRET
)


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    session['oauth_token'] = None
    return bitbucket.authorize(callback=url_for('bitbucket_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))


@app.route('/login/authorized')
@bitbucket.authorized_handler
def bitbucket_authorized(resp):
    if resp is None:
        return 'Access denied'
    session['oauth_token'] = (resp['oauth_token'], resp['oauth_token_secret'])
    user = bitbucket.get('user').data['user']
    return 'Logged in as username=%s display_name=%s redirect=%s' % \
        (user['username'], user['display_name'], request.args.get('next'))


@bitbucket.tokengetter
def get_bitbucket_oauth_token():
    return session.get('oauth_token')


if __name__ == '__main__':
    app.run()
