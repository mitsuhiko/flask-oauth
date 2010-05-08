from flask import Flask, request, redirect, url_for, session, flash, g, \
     render_template
from flaskext.oauth import OAuth

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# configuration
DATABASE_URI = 'sqlite:////tmp/flask-oauth.db'
SECRET_KEY = 'development key'
DEBUG = True

# setup flask
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

# Use Twitter as example remote application
twitter = oauth.remote_app('twitter',
    base_url='http://api.twitter.com/1/',
    request_token_url='http://api.twitter.com/oauth/request_token',
    access_token_url='http://api.twitter.com/oauth/access_token',
    authorize_url='http://api.twitter.com/oauth/authenticate',
    consumer_key='xBeXxg9lyElUgwZT6AZ0A',
    consumer_secret='aawnSpNTOVuDCjx7HMh6uSXetjNN8zWLpZwCEU4LBrk'
)

# setup sqlalchemy
engine = create_engine(DATABASE_URI)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    Base.metadata.create_all(bind=engine)


class User(Base):
    __tablename__ = 'users'
    id = Column('user_id', Integer, primary_key=True)
    name = Column(String(60))
    oauth_token = Column(String(200))
    oauth_secret = Column(String(200))

    def __init__(self, name, oauth_token, oauth_secret):
        self.name = name
        self.oauth_token = oauth_token
        self.oauth_secret = oauth_secret


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.after_request
def after_request(response):
    db_session.remove()
    return response


@twitter.tokengetter
def get_twitter_token():
    user = g.user
    if user is not None:
        return user.oauth_token, user.oauth_secret


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/tweet', methods=['POST'])
def tweet():
    status = request.form['tweet']
    if not status:
        return redirect(url_for('index'))
    resp = twitter.post('statuses/update.json', data={
        'status':       status
    })
    if resp.status == 403:
        flash('Your tweet was too long.')
    else:
        flash('Successfully tweeted your tweet (ID: #%s)' % resp.data['id'])
    return redirect(url_for('index'))


@app.route('/login')
def login():
    callback = url_for('oauth_authorized', next=request.args.get('next')
                       or request.referrer)
    return twitter.authorize(callback=callback)


@app.route('/logout')
def logout():
    session.pop('user_id')
    flash('You were signed out')
    return redirect(request.referrer or url_for('index'))


@app.route('/oauth-authorized')
@twitter.authorized_handler
def oauth_authorized(resp):
    user = User.query.filter_by(name=resp['screen_name']).first()

    # user never signed on on
    if user is None:
        user = User(resp['screen_name'],
                    resp['oauth_token'],
                    resp['oauth_token_secret'])
        db_session.add(user)

    # in case the user temporarily revoked out access, we have to
    # update the authentication token and secret in the database
    else:
        user.oauth_token = resp['oauth_token']
        user.oauth_token_secret = resp['oauth_token_secret']

    db_session.commit()
    session['user_id'] = user.id
    flash('You were signed in')
    return redirect(request.args.get('next') or url_for('index'))


if __name__ == '__main__':
    app.run()
