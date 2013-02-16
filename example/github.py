from flask import Flask, redirect, url_for, session, request
from flask_oauth import OAuth


SECRET_KEY = 'development key'
DEBUG = True
GITHUB_CLIENT_ID = '<Client-ID>'
GITHUB_CLIENT_SECRET = '<Client-Secret>'


app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

github = oauth.remote_app('github',
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    consumer_key=GITHUB_CLIENT_ID,
    consumer_secret=GITHUB_CLIENT_SECRET,
    # add scope like this: {'scope': 'user:email'}
    request_token_params=None
)


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return github.authorize(callback=url_for('github_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))


@app.route('/login/authorized')
@github.authorized_handler
def github_authorized(resp):
    if resp is None:
        return 'Access denied: error=%s' % (request.args['error'])
    session['oauth_token'] = (resp['access_token'], '')
    user = github.get('/user')
    return 'Logged in as id=%s login=%s redirect=%s' % \
        (user.data['id'], user.data['login'], request.args.get('next'))


@github.tokengetter
def get_github_oauth_token():
    return session.get('oauth_token')


if __name__ == '__main__':
    app.run()
