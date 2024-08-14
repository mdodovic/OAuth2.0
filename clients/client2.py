from urllib.parse import urljoin
from flask import Flask, jsonify
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

        return jsonify(response.json())


@app.route('/get-client2-resource')
def get_client1_resource():
    with app.app_context():
        global token2
        resource_url = urljoin(resource_server_url, 'get-client1-resource')
        headers = {
            'Authorization': f'Bearer {token2}'
        }
        resource_response = requests.get(resource_url, headers=headers)
        if resource_response.status_code == 200:
            return resource_response.json().get('message')
        return 'Failed to get resource from Client1'


if __name__ == '__main__':
    get_token()
    print('Successful response:', get_client1_resource())
    app.run(host="localhost", port=5005, debug=True)