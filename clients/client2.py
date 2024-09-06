from functools import wraps
from urllib.parse import urljoin
from flask import Flask, Response, jsonify
import requests

app = Flask(__name__)

oauth_server_url = 'http://localhost:5003'
resource_server_url = 'http://localhost:5004'

client2_id = 'client2_id_test'
client2_secret = 'client2_secret_test'
token2 = None


def get_token():
    with app.app_context():
        global token2

        # Obtain the token from the OAuth provider
        token_url = urljoin(oauth_server_url, 'oauth/token')
        data = {
            'grant_type': 'client_credentials',
            'client_id': client2_id,
            'client_secret': client2_secret,
        }
        response = requests.post(token_url, data=data)
        token2 = response.json().get('access_token')

        print("Client2 Token: ", token2)

        return token2


def token_required(f):
    """
    Decorator to ensure that the token is valid before executing the function
    The flow is to call decorated function, if it returns 401, refresh the token and retry
    """	
    @wraps(f)
    def decorated_function(*args, **kwargs):
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


@app.route('/get-client2-resource')
@token_required
def get_client1_resource():
    with app.app_context():
        global token2

        resource_url = urljoin(resource_server_url, 'get-client1-resource')
        headers = {
            'Authorization': f'Bearer {token2}'
        }
        resource_response = requests.get(resource_url, headers=headers)

        if resource_response.status_code == 200:
            return jsonify(resource_response.json().get('message'))
        else:
            return Response('Failed to get resource from Client1', status=resource_response.status_code)


if __name__ == '__main__':
    get_token()
    response = get_client1_resource()
    print('Successful response #1:', response.get_data(as_text=True))
    
    # Illustrative example of expired token
    token2 = "Invalid Token"

    response = get_client1_resource()
    print('Successful response #2:', response.get_data(as_text=True))

    app.run(host="localhost", port=5005, debug=True)
