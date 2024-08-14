from flask import Blueprint, jsonify, request
from oauth_database_management import Client, save_client
from oauth_server import app, require_oauth


client_registration_bp = Blueprint('client_registration', __name__)


def manually_create_client(client_id, client_secret):
    """
    Manually create a client. If client is already created, return a message
    """
    with app.app_context():
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            grant_type='client_credentials',
            token_endpoint_auth_method='client_secret_basic'
        )

        client = save_client(client)

        if client is None:
            return f'Client {client_id} already exists!'

        return f'Client {client} created successfully!'


@client_registration_bp.route('/register-client', methods=['POST'])
@require_oauth('profile')
def register_client():
    """
    Register a new client. This is left because it is common practice to 
    register new clients via authorize endpoint 
    """
    data = request.get_json()
    
    if data is None:
        return jsonify({'error': 'No data provided'}), 400

    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    
    if client_id is None:
        return jsonify({'error': 'Client ID is required'}), 400
    if client_secret is None:
        return jsonify({'error': 'Client secret is required'}), 400

    grant_type = 'client_credentials'
    token_endpoint_auth_method = 'client_secret_basic'

    client = Client(
        client_id=client_id,
        client_secret=client_secret,
        grant_type=grant_type,
        token_endpoint_auth_method=token_endpoint_auth_method
    )

    save_client(client)

    if client is None:
        return jsonify({'error': 'Client already exists!'}), 400
    
    return jsonify({'message': f'Client {client.client_id} created successfully!'})