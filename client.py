import requests
from flask import Flask, jsonify

app = Flask(__name__)

client_id = 'client_id_test'  # Replace with actual client_id
client_secret = 'client_secret_test'  # Replace with actual client_secret
token = None

@app.route('/get_resource', methods=['GET'])
def get_resource():
    global token 

    resource_url = 'http://192.168.1.86:5003/api/resource'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    resource_response = requests.get(resource_url, headers=headers)
    return jsonify(resource_response.json())


@app.route('/get-token', methods=['GET'])
def get_token():
    global token 

    # Obtain the token from the OAuth provider
    token_url = 'http://192.168.1.86:5003/oauth/token'
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }
    response = requests.post(token_url, data=data)

    token = response.json().get('access_token')
    print(token)
    return jsonify(response.json())



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)