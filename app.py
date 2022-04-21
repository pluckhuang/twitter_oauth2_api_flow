# twitter-oauth2-client

from flask import redirect, request, render_template, session, abort, Flask
import hashlib
from urllib.parse import urlencode
from lib import tools


app = Flask(__name__)
app.secret_key = '!secret'


confidentialClient = {
    'client_id': config["client_id"],
    'client_secret': config["client_secret"],
}

publicClient = {
    'client_id': config["client_id"],
    'token_endpoint_auth_method': 'none',
}

client = publicClient if config['client_type'] == 'PUBLIC' else confidentialClient


@app.route('/')
def index():
    """
    :return: the index page with the tokens, if set.
    """
    user = None
    if 'session_id' in session:
        user = _session_store.get(session['session_id'])

    if 'base_url' not in config or not config['base_url']:
        config['base_url'] = request.base_url

    if 'redirect_uri' not in config:
        config['redirect_uri'] = config['base_url'].rstrip('/') + '/callback'

    if isinstance(user, (bytes, str)):
        # User is a string! Probably a bunch of HTML from a previous error. Just bail and hope for the best.
        return user

    if user:
        if user.front_end_id_token:
            user.front_end_id_token_json = decode_token(
                user.front_end_id_token)

        if user.front_end_access_token:
            user.front_end_access_token_json = decode_token(
                user.front_end_access_token)

        if user.id_token:
            user.id_token_json = decode_token(user.id_token)

        if user.access_token:
            user.access_token_json = decode_token(user.access_token)

        return render_template('index.html',
                               server_name=config['issuer'],
                               session=user, flow=session.get("flow", "code"))
    else:
        client_data = client.get_client_data()
        dynamically_registered = bool(
            client_data and 'client_id' in client_data)
        using_static_registration = "client_id" in config and "client_secret" in config
        registered = dynamically_registered or using_static_registration
        client_id = client_data['client_id'] if dynamically_registered else config.get(
            "client_id", "")

        return render_template('welcome.html',
                               registered=registered,
                               client_id=client_id,
                               server_name=config['issuer'],
                               client_data=client_data,
                               flow="code",
                               using_dynamic_registration=dynamically_registered,
                               authorization_endpoint=config["authorization_endpoint"])


@app.route('/callback')
def oauth_callback():
    if session.get("flow", None) != "code":
        # This is the callback for a hybrid or implicit flow
        return render_template('index.html')

    if 'state' not in session or session['state'].decode() != request.args['state']:
        return create_error('Missing or invalid state')

    if "code_verifier" not in session:
        return create_error("No code_verifier in session")

    if 'code' not in request.args:
        return create_error('No code in response')

    user = callback(request.args)

    session['session_id'] = tools.generate_random_string()
    _session_store[session['session_id']] = user

    return redirect_with_baseurl('/')


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
    if _app:
        user = UserSession()
        if 'session_id' in session:
            user = _session_store.get(session['session_id'])
        return render_template('index.html',
                               flow="code",
                               server_name=_config['issuer'],
                               session=user,
                               error=message)


def callback(params):
    session.pop('state', None)

    try:
        token_data = _client.get_token(
            params['code'], session["code_verifier"].decode())
    except Exception as e:
        return create_error('Could not fetch token(s)', e)

    # Store in basic server session, since flask session use cookie for storage
    user = UserSession()

    if 'access_token' in token_data:
        user.access_token = token_data['access_token']

    if 'refresh_token' in token_data:
        user.refresh_token = token_data['refresh_token']

    return user


@app.route('/start-login')
def start_oauth_flow():

    state = tools.generate_random_string()
    code_verifier = tools.generate_random_string(100)
    code_challenge = tools.base64_urlencode(
        hashlib.sha256(code_verifier).digest())

    request_args = {
        "client_id": client['client_id'],
        "redirect_uri": config['redirect_uri'],
        "response_type": 'code',
        "scope": config['scope'],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": 'S256',
        "aud": config['issuer']
    }

    delimiter = "?" if config['authorization_endpoint'].find("?") < 0 else "&"
    login_url = "{}{}{}".format(
        config['authorization_endpoint'], delimiter, urlencode(request_args))

    print("Redirect to %s" % login_url)

    return redirect(login_url)
