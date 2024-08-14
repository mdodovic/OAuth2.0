import os
import secrets
from uuid import uuid4 
from flask import Flask, request, jsonify
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidGrantError, InsecureTransportError
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from config import SECRET_KEY, DATABASE_URL
from oauth_database_management import query_token, save_client, session, Client, Token, query_client, save_token 


# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
# SQLite will be used for the sake of simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    """
    Client Credentials Grant
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
        if client:
            if client.client_secret == client_secret:
                return client
            else:
                InvalidGrantError(description='DEBUG: Client secret does not match')
        else:
            InvalidGrantError(description='Client not found in DB')
        raise InvalidGrantError(description='Invalid client credentials')


# Initialize Authorization Server
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)


# Register the Client Credentials Grant
authorization.register_grant(ClientCredentialsGrant)

def generate_bearer_token(grant_type, client, user=None, scope=None, expires_in=None, include_refresh_token=True):
    """
    Generate a Bearer Token
    """
    token = {
        'token_type': 'Bearer',
        'access_token': secrets.token_urlsafe(48),  # Generate a random access token
        'expires_in': expires_in or 3600,  # Token expiration time (1 hour by default)
        'scope': scope or 'profile'  # Default to 'profile' if no scope is provided
    }
    if include_refresh_token:
        token['refresh_token'] = secrets.token_urlsafe(48)  # Optionally add a refresh token

    return token


# Register the token generator with the authorization server
authorization.register_token_generator('default', generate_bearer_token)


# Custom Bearer Token Validator
class BearerTokenValidator(_BearerTokenValidator):
    """
    Custom Bearer Token Validator
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
bearer_token_validator = BearerTokenValidator()
require_oauth.register_token_validator(bearer_token_validator)


# Routes
@app.route('/oauth/token', methods=['POST'])
def issue_token():
    """
    Issue a token
    """
    scope = 'profile'  # Specify the required scope here NOT USED 
    try:
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


# Add the introspection endpoint
@app.route('/oauth/introspect', methods=['POST'])
@require_oauth('profile')
def check_token():
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
