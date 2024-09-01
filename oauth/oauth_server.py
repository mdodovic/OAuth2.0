import os
import secrets
from uuid import uuid4 
from flask import Flask, request, jsonify
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidGrantError, InsecureTransportError
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from config import DEFAULT_SCOPE, SECRET_KEY, DATABASE_URL, TOKEN_EXPIRES_IN
from oauth_database_management import query_token, save_client, session, Client, Token, query_client, save_token 


# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
# SQLite will be used for the sake of simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL


# Initialize Authorization Server
# The Authorization Server is responsible for managing the authorization and token endpoints
# It also manages the token generation and introspection endpoints
# 2 functions are passed to the AuthorizationServer:
# - query_client: a function that queries the database for a client
# - save_token: a function that saves the token to the database 
#   - This function needs request parameter (a http request object)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    """
    Client Credentials Grant
    Used for check if the client is authorized to use the token endpoint
    """
    @staticmethod
    def check_token_endpoint(request):
        """
        Check if the request is a token endpoint request
        """
        return request.grant_type == 'client_credentials'


    @staticmethod
    def check_authorization_endpoint(request):
        """
        Check if the request is an authorization endpoint request
        """
        # This grant does not support authorization endpoint requests
        return False


    def validate_token_request(self):
        """ 
        Validate the token request
        """
        client_id = request.form['client_id']
        client_secret = request.form['client_secret']
        client = query_client(client_id)
        if client is not None:
            if client.check_client_secret(client_secret):
                return client
            else:
                InvalidGrantError(description='DEBUG: Client secret does not match')
        else:
            InvalidGrantError(description='Client not found in DB')
        raise InvalidGrantError(description='Invalid client credentials')


# Register the Client Credentials Grant
authorization.register_grant(ClientCredentialsGrant)


def generate_bearer_token(grant_type, client, user=None, scope=None, expires_in=None, include_refresh_token=True):
    """
    Generate a Bearer Token
    """
    token = {
        'token_type': 'Bearer',
        'access_token': secrets.token_urlsafe(48),
        'expires_in': expires_in or TOKEN_EXPIRES_IN,
        'scope': scope or DEFAULT_SCOPE
    }
    if include_refresh_token:
        token['refresh_token'] = secrets.token_urlsafe(48)

    return token


# Register the token generator with the authorization server
authorization.register_token_generator('default', generate_bearer_token)


class BearerTokenValidatorImplementation(_BearerTokenValidator):
    """
    Bearer Token Validator
    Checks if the token is valid
    """
    def __init__(self):
        super().__init__(token_model=Token)

    def authenticate_token(self, token_string):
        token = query_token(access_token=token_string)
        if token:
            return token
        return None
    

# Resource Protector
require_oauth = ResourceProtector()
require_oauth.register_token_validator(BearerTokenValidatorImplementation())


@app.route('/oauth/token', methods=['POST'])
def issue_token():
    """
    Endpoint to issue a token
    """
    try:
        # to provide parameters (scope, expires_in, include_refresh_token) to the generate_token method
        # they cannot be passed directly, in stack call of this method, some of the methods throws 
        # NotImplementedError, so we need to pass them as for example global variables
        # for the demo purposes, we will stick to default scope and default expiration time, which
        # is set in the config.py file
        return authorization.create_token_response()
    except InsecureTransportError:
        return jsonify({"error": "Insecure transport detected. Please use HTTPS or set OAUTHLIB_INSECURE_TRANSPORT=1 for development."}), 400
    except InvalidGrantError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Unexpected error occurred"}), 500


class IntrospectEndpointImplementation(IntrospectionEndpoint):
    def query_token(self, token, token_type_hint):
        # Example: Replace with actual token lookup in your database
        token_data = query_token(access_token=token)
        if token_data and not token_data.is_expired():
            return token_data
        return None

    def introspect_token(self, token_data):
        if token_data:
            return {
                "active": True,
                "client_id": token_data.client_id,
                "token_type": token_data.token_type,
                "scope": token_data.scope,
                "expires_in": token_data.expires_in,
                "created_at": token_data.created_at,
                "is_expired": token_data.is_expired(),
                "is_revoked": token_data.is_revoked()
            }
        return {"active": False}


@app.route('/oauth/introspect', methods=['POST'])
@require_oauth('profile')
def check_token():
    """
    Endpoint to check if a token is valid. 
    It is used with communication outside of this OAuth server, when 2 parts communicates 
    and one part needs to check if the token provided by the other part is valid.
    """
    token = request.form.get('token')
    if token is None:
        return jsonify({"active": False}), 400

    introspection = IntrospectEndpointImplementation(authorization)
    token_data = introspection.query_token(token, None)

    response = introspection.introspect_token(token_data)
    return jsonify(response)


if __name__ == '__main__':

    from client_registration import manually_create_client
    # For the demo purposes, we will create admin client and 2 test clients
    status = manually_create_client(client_id='admin_client', client_secret='admin_secret')
    print(status)

    status = manually_create_client(client_id='client_id_test', client_secret='client_secret_test')
    print(status)

    status = manually_create_client(client_id='client2_id_test', client_secret='client2_secret_test')
    print(status)

    # Register the client registration blueprint
    from client_registration import client_registration_bp
    app.register_blueprint(client_registration_bp)

    app.run(host='localhost', port=5003, debug=True)
