# OAuth2.0

This repository demonstrates a simple OAuth2 setup using Flask and Authlib for both the Authorization Server and multiple Resource Servers. It includes examples of Client Credentials Flow, token validation using introspection, and enforcing token protection on resources.

### Project Structure

##### oauth/oauth_server.py
Implements the OAuth2 authorization server, responsible for issuing tokens and introspecting them.

##### client/client.py
A resource server that validates access tokens issued by the authorization server and protects its endpoints.

##### client/client2.py
A resource server acting as a client of client1, interacting with its protected resources using OAuth tokens.

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
This project is licensed under the MIT License.
