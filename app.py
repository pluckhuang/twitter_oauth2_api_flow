import hashlib
import sys
import json
import requests
from requests.auth import HTTPBasicAuth
import base64
from tools import (decode_token, generate_random_string,
                   print_json, base64_urlencode)
from config import Config
from client import Client
from urllib.parse import urlencode
from flask import redirect, request, render_template, session, abort, Flask
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

app = Flask(__name__)


class UserSession:
    def __init__(self):
        pass

    access_token = None
    refresh_token = None
    id_token = None
    access_token_json = None
    id_token_json = None
    name = None
    api_response = None
    front_end_id_token = None
    front_end_id_token_json = None
    front_end_access_token = None




@app.route('/likes')
def likes():
    print('uid: ' + request.args.get('uid'))
    url = 'https://api.twitter.com/2/users/{0}/liked_tweets?tweet.fields=id'.format(request.args.get('uid'))
    auth_token = request.args.get('auth_token')
    headers = {
        "Authorization": 'Bearer {}'.format(auth_token),
    }
    print(url)

    r = requests.get(url, headers=headers)
    return r.json()


@app.route('/tlikes')
def tlikes():
    print('uid: ' + request.args.get('tid'))
    url = 'https://api.twitter.com/2/tweets/{0}/liking_users'.format(request.args.get('tid'))
    auth_token = request.args.get('auth_token')
    headers = {
        "Authorization": 'Bearer {}'.format(auth_token),
    }
    print(url)

    r = requests.get(url, headers=headers)
    return r.json()


@app.route('/following')
def following():
    print('uid: ' + request.args.get('uid'))
    url = 'https://api.twitter.com/2/users/{0}/following?user.fields=username,url'.format(request.args.get('uid'))
    auth_token = request.args.get('auth_token')
    headers = {
        "Authorization": 'Bearer {}'.format(auth_token),
    }
    print(url)

    r = requests.get(url, headers=headers)
    return r.json()


@app.route('/user_info')
def user_info():
    url = 'https://api.twitter.com/2/users/{}?&user.fields=created_at&tweet.fields=created_at'.format(request.args.get('user_id'))
    auth_token = request.args.get('auth_token')
    headers = {
        "Authorization": 'Bearer {}'.format(auth_token)
    }
    print(url)
    r = requests.get(url, headers=headers)
    return r.json()


@app.route('/who')
def check():
    url = 'https://api.twitter.com/2/users/me'
    auth_token = request.args.get('auth_token')
    headers = {
        "Authorization": 'Bearer {}'.format(auth_token)
    }
    r = requests.get(url, headers=headers)
    return r.json()


@app.route('/get_bearer_token')
def direct_token():
    url = 'https://api.twitter.com/oauth2/token'
    # basic_token = base64.b64encode("{0}:{1}".format(config['client_id'], config['client_secret']))
    print(config['client_id'], config['client_secret'])

    client_id = config['client_id']
    client_secret = config['client_secret']

    data = {
        "grant_type": "client_credentials"
    }
    client = BackendApplicationClient(client_id=client_id)
    oauth = OAuth2Session(client=client)
    token = oauth.fetch_token(
        token_url=url,
        client_id=client_id,
        client_secret=client_secret
    )
    return token


@app.route('/')
def start_oauth_flow():

    state = generate_random_string()
    code_verifier = generate_random_string(100)
    code_challenge = base64_urlencode(
        hashlib.sha256(code_verifier).digest())

    session['state'] = state
    session['code_verifier'] = code_verifier
    print("init session:")
    print(session)
    request_args = {
        "client_id": config['client_id'],
        "redirect_uri": config['redirect_uri'],
        "response_type": 'code',
        "scope": config['scope'],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": 'S256',
    }

    delimiter = "?" if config['authorization_endpoint'].find("?") < 0 else "&"
    login_url = "{}{}{}".format(
        config['authorization_endpoint'], delimiter, urlencode(request_args))

    print("Redirect to %s" % login_url)

    return redirect(login_url)


@app.route('/callback')
def oauth_callback():
    print("in callback session:")
    print(request.args)

    if 'state' not in session or session['state'].decode() != request.args['state']:
        return create_error('Missing or invalid state')
    if "code_verifier" not in session:
        return create_error("No code_verifier in session")
    if 'code' not in request.args:
        return create_error('No code in response')

    token_data = callback(request.args)
    session['token_data'] = token_data
    return token_data


def redirect_with_baseurl(path):
    return redirect(config['base_url'] + path)


def create_error(message, exception=None):
    """
    Print the error and output it to the page
    :param exception:
    :param message:
    :return: redirects to index.html with the error message
    """
    print('Caught error!')
    print(message, exception)
    if app:
        user = UserSession()
        if 'session_id' in session:
            user = _session_store.get(session['session_id'])
        return render_template('index.html',
                               flow="code",
                               server_name=config['issuer'],
                               session=user,
                               error=message)


def callback(params):
    session.pop('state', None)

    try:
        token_data = client.get_token(
            params['code'], session["code_verifier"].decode())
    except Exception as e:
        return create_error('Could not fetch token(s)', e)

    return token_data


def load_config():
    """
    Load config from the file given by argument, or settings.json
    :return:
    """
    if len(sys.argv) > 1:
        print("Using an alternative config file: %s" % sys.argv[1])
        filename = sys.argv[1]
    else:
        filename = 'settings.json'
    config = Config(filename)

    return config.load_config()


if __name__ == '__main__':

    # load the config
    config = load_config()

    client = Client(config)

    # create a session store
    _session_store = {}

    # initiate the app
    app.secret_key = generate_random_string()

    # some default values
    if 'port' in config:
        port = int(config['port'])
    else:
        port = 5443

    _disable_https = 'disable_https' in config and config['disable_https']

    if 'base_url' not in config:
        config['base_url'] = 'https://localhost:%i' % port

    debug = config['debug'] = 'debug' in config and config['debug']

    if debug:
        print('Running conf:')
        print_json(config)

    if _disable_https:
        app.run('0.0.0.0', debug=debug, port=port)
    else:
        app.run('0.0.0.0', debug=debug, port=port, ssl_context='adhoc')
