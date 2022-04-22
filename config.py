import json
import os



class Config():

    _keys = ['api_endpoint',
             'authn_parameters',
             'authorization_endpoint',
             'base_url',
             'client_id',
             'client_secret',
             'dcr_client_id',
             'dcr_client_secret',
             'debug',
             'disable_https',
             'discovery_url',
             'issuer',
             'audience',
             'jwks_uri',
             'end_session_endpoint',
             'port',
             'redirect_uri',
             'revocation_endpoint',
             'scope',
             'token_endpoint',
             'verify_ssl_server']

    def __init__(self, filename):
        self.filename = filename

    def load_config(self):
        """
        Load config from file and environment
        :return:
        """
        self._load_from_file(self.filename)
        self._update_config_from_environment()
        return self.store

    def _load_from_file(self, filename):
        print('Loading settings from %s' % filename)
        with open(filename, 'r') as f:
            self.store = json.loads(f.read())

    def _update_config_from_environment(self):
        from_env = {}
        for key in self._keys:
            env = os.environ.get(key.upper(), None)
            if env:
                from_env[key] = env
        self.store.update(from_env)
