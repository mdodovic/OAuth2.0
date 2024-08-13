import os

# Environment setup for non-HTTPS development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

SECRET_KEY = 'secret'
DATABASE_URL = 'sqlite:///oauth_db.db'
