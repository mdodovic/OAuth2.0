import os
import secrets
from uuid import uuid4 
from flask import Flask, request, jsonify
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidGrantError, InsecureTransportError
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator
from authlib.integrations.sqla_oauth2 import create_query_client_func, create_save_token_func
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base

from datetime import datetime, timedelta, timezone


# Environment setup for non-HTTPS development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecret'

# Here it is decided to use SQLite for the sake of simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oauth_db.db'

# Database setup
Base = declarative_base()
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)
session = Session()

# Database Models
class Client(Base):
    __tablename__ = 'clients'
    id = Column(Integer, primary_key=True)
    client_id = Column(String, unique=True, nullable=False)
    client_secret = Column(String, nullable=False)
    grant_type = Column(String, nullable=False)
    token_endpoint_auth_method = Column(String, nullable=False)

class Token(Base):
    __tablename__ = 'tokens'
    id = Column(Integer, primary_key=True)
    client_id = Column(String, ForeignKey('clients.client_id'), nullable=False)
    access_token = Column(String, unique=True, nullable=False)
    token_type = Column(String, nullable=False)
    scope = Column(String)
    expires_in = Column(Integer)
    created_at = Column(Integer, default=lambda: int(datetime.now(timezone.utc).timestamp()))

    def is_expired(self):
        """
        Calculate if the token is expired
        """
        creation_time = datetime.fromtimestamp(self.created_at, tz=timezone.utc)
        expiration_time = creation_time + timedelta(seconds=self.expires_in)
        return datetime.now(timezone.utc) > expiration_time

    def is_revoked(self):
        """ 
        Check if the token is revoked
        """
        # In this example, we do not revoke tokens
        return False
    
    def get_scope(self):
        """
        Get the scope of the token
        """
        return self.scope
    
# Initialize the database
Base.metadata.drop_all(engine, tables=[Token.__table__])
Base.metadata.create_all(engine)

# Client Credentials Grant class
class ClientCredentialsGrant(grants.ClientCredentialsGrant):
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
        client = session.query(Client).filter_by(client_id=client_id).first()
        if client:
            if client.client_secret == client_secret:
                return client
            else:
                InvalidGrantError(description='DEBUG: Client secret does not match')
        else:
            InvalidGrantError(description='Client not found in DB')
        raise InvalidGrantError(description='Invalid client credentials')


def query_client(client_id):
    """
    Query the client from the database
    """
    return session.query(Client).filter_by(client_id=client_id).first()


def save_token(token, request):
    """
    Save the token to the database
    """
    if request.data is None:
        raise InvalidGrantError(description='Data authentication failed')
    item = Token(
        client_id=request.data.get('client_id'),
        access_token=token['access_token'],
        token_type=token['token_type'],
        scope=token.get('scope'),
        expires_in=token['expires_in']
    )
    session.add(item)
    session.commit()

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
        token = session.query(Token).filter_by(access_token=token_string).first()
        if token:
            return token
        return None

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return False

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
    scope = 'profile'  # Specify the required scope here
    print("DEBUG: issue_token called")  # Ensure this line is printed
    try:
        resp = authorization.create_token_response()
        print(resp)
        return resp
    except InsecureTransportError:
        return jsonify({"error": "Insecure transport detected. Please use HTTPS or set OAUTHLIB_INSECURE_TRANSPORT=1 for development."}), 400
    except InvalidGrantError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print("DEBUG: Unexpected error:", str(e))
        return jsonify({"error": "Unexpected error occurred"}), 500


@app.route('/api/resource', methods=['GET'])
@require_oauth('profile')
def api_resource():
    """
    Protected Resource
    """
    return jsonify({'message': 'Hello, World!'})


@app.route('/create_client', methods=['POST'])
def create_client(cid, csecret):
    """
    Create a new client
    """
    with app.app_context():
        client = Client(
            client_id=cid,
            client_secret=csecret,
            grant_type='client_credentials',
            token_endpoint_auth_method='client_secret_basic'
        )
        session.add(client)
        session.commit()
        return jsonify({'message': 'Client created successfully!'})


def create_admin_client():
    """
    Create an admin client
    """
    with app.app_context():
        client = Client(
            client_id='admin_client',
            client_secret='admin_secret',
            grant_type='client_credentials',
            token_endpoint_auth_method='client_secret_basic'
        )
        existing_admin_client = session.query(Client).filter_by(client_id='admin_client').first()
        if existing_admin_client:
            return jsonify({'message': 'Admin client already exists!'})
        session.add(client)
        session.commit()
        return jsonify({'message': 'Admin client created successfully!'})


# Main block to run the Flask app
if __name__ == '__main__':
    # Create admin client
    create_admin_client()
    #create_client('client_id_test', 'client_secret_test')
    app.run(host='0.0.0.0', port=5003, debug=True)
