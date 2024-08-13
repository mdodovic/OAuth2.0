from flask import Flask, jsonify
import requests

app = Flask(__name__)

client2_id = 'client2_id_test'
client2_secret = 'client2_secret_test'
token2 = None


def get_token():
    with app.app_context():
        global token2

        # Obtain the token from the OAuth provider
        token_url = 'http://192.168.1.86:5003/oauth/token'
        data = {
            'grant_type': 'client_credentials',
            'client_id': client2_id,
            'client_secret': client2_secret,
        }
        response = requests.post(token_url, data=data)
        token2 = response.json().get('access_token')

        print("Client2 Token: ", token2)

        return jsonify(response.json())


def get_client1_resource():
    with app.app_context():
        global token2
        resource_url = 'http://192.168.1.86:5004/get-client1-resource'
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
    app.run(host="0.0.0.0", port=5005, debug=True)