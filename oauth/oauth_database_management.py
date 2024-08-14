from authlib.integrations.sqla_oauth2 import create_query_client_func, create_save_token_func
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from authlib.oauth2.rfc6749.errors import InvalidGrantError

from config import DATABASE_URL


# Database setup
Base = declarative_base()
engine = create_engine(DATABASE_URL)
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
Base.metadata.create_all(engine)


# Utility functions
def query_client(client_id):
    """
    Query the client from the database
    """
    return session.query(Client).filter_by(client_id=client_id).first()


def query_token(access_token):
    """
    Query the token from the database
    """
    return session.query(Token).filter_by(access_token=access_token).first()


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


def save_client(client):
    """
    Save the client to the database. If the client already exists, return a message
    """

    existing_client = query_client(client.client_id)

    if existing_client is not None:
        return None

    session.add(client)
    session.commit()

    return query_client(client.client_id)
