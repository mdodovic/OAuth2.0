from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import urljoin
from flask import Flask, request, jsonify
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator
import requests
from flask import Flask, jsonify

app = Flask(__name__)

oauth_server_url = 'http://localhost:5003'

client_id = 'client_id_test'
client_secret = 'client_secret_test'
token = None


def get_token():
    with app.app_context():
        global token 

        # Obtain the token from the OAuth provider
        token_url = urljoin(oauth_server_url, 'oauth/token')
        data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        }
        response = requests.post(token_url, data=data)
        token = response.json().get('access_token')

        print("Client1 Token: ", token)

        return jsonify(response.json())


def token_required(f):
    """
    Decorator to ensure that the token is valid before executing the function
    The flow is to call decorated function, if it returns 401, refresh the token and retry
    """	
    @wraps(f)
    def decorated_function(*args, **kwargs):
        global token2

        # First attempt to execute the original function
        result = f(*args, **kwargs)
        
        # if everything is ok, return the result without any changes, like this wrapper does not exist

        # if the result is 401 (Unauthorized), refresh the token and retry
        if result.status_code == 401:
            print("Received 401, refreshing token and retrying...")
            get_token()  # Refresh the token
            
            # This is an attempt to execude the original function with the new token
            result = f(*args, **kwargs)  

        return result

    return decorated_function


class IntrospectionToken:
    """
    A wrapper class to handle token data returned from introspection endpoint
    This class, apart from the token data, needs to contain methods: 
        - is_expired() : check if the token is expired 
        - get_scope() : get the scope of the token 
        - is_revoked() : check if the token is revoked 
    And those methods should only return the values from the token data which were provided by the 
    OAuth introspection endpoint.
    """
    def __init__(self, token_data):
        self.token_data = token_data

    def is_expired(self):
        return self.token_data.get('is_revoked')

    def get_scope(self):
        return self.token_data.get('scope')

    def is_revoked(self):
        return self.token_data.get('is_revoked')


class BearerTokenValidatorInterceptor(_BearerTokenValidator):
    def authenticate_token(self, token_string):
        introspection_url = urljoin(oauth_server_url, 'oauth/introspect')
        headers = {
            # Use Client1's token for authentication of introspection
            'Authorization': f'Bearer {token}'  
        }
        data = {
            # Client2's token which is being introspected
            'token': token_string  
        }
        introspection_response = requests.post(introspection_url, data=data, headers=headers)

        if introspection_response.status_code == 200:
            token_data = introspection_response.json()
            if token_data.get('active'):
                # We need a wrapper class to handle the token data
                # this class needs to contain methods: is_expired(), get_scope(), is_revoked()
                return IntrospectionToken(token_data) 
        return None


# Resource Protector to enforce token validation
require_oauth = ResourceProtector()
# This protector intercept tokens and validate them by 
# asking the OAuth provider to introspect the token 
require_oauth.register_token_validator(BearerTokenValidatorInterceptor())


@app.route('/get-client1-resource', methods=['GET'])
@token_required
@require_oauth('profile')
def get_client_resource():
    return jsonify({'message': 'Client 1 resource'}), 200


if __name__ == '__main__':
    get_token()
    app.run(host='localhost', port=5004, debug=True)