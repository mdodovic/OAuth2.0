# OAuth2.0

This project demonstrates a complete OAuth2 authorization and resource server setup using Flask and Authlib, showcasing the Client Credentials flow. It enables secure API interactions between multiple resource servers (Client1 and Client2) by enforcing token validation using OAuth2 tokens. The setup allows:

- Centralized token management through an authorization server.
- Secure access to protected resources with OAuth2 tokens.
- Token introspection to validate and manage the lifecycle of access tokens.
- Automatic token refreshing for seamless interaction between clients.

The project is built to provide a straightforward example of integrating OAuth2 in a microservice-based architecture, where resource servers communicate securely by validating OAuth tokens through a central authorization server.

The implementation follows the Client Credentials Grant flow, where no user interaction is required to obtain tokens—making it ideal for machine-to-machine authentication. This setup can be easily extended or customized to fit various application needs that require secure service communication.

### Project Structure

##### oauth/oauth_server.py
Implements the OAuth2 authorization server responsible for issuing tokens and introspecting them.

##### client/client.py
A resource server that validates access tokens issued by the authorization server and protects its endpoints.

##### client/client2.py
A resource server acts as a client of client1, interacting with its protected resources using OAuth tokens.

### How to Run
#### Install the required dependencies:
``` bash
pip install -r requirements.txt
```

#### Steps to Start the Servers
1. Run the OAuth Authorization Server:
``` bash
python ./oauth/oauth_server.py
``` 
The OAuth2 Authorization Server will start on http://localhost:5003.

2. Run Client1 Resource Server:
```bash
python ./client/client1.py
```
This starts Client1's resource server on http://localhost:5004.

3. Run Client2 Resource Server:
```bash
python ./client/client2.py
```
This starts Client2's resource server on http://localhost:5005.

Interact with Client1's Resources: You can access the protected resources of Client1 through Client2, where Client2 will automatically handle token refreshing in case of token expiration or unauthorized access.

### License
This project is licensed under the GNU General Public License v3.0.
