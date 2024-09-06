# OAuth2.0

This repository demonstrates a simple OAuth2 setup using Flask and Authlib for both the Authorization Server and multiple Resource Servers. It includes examples of Client Credentials Flow, token validation using introspection, and enforcing token protection on resources.

### Project Structure

##### oauth/oauth_server.py
Implements the OAuth2 authorization server, responsible for issuing tokens and introspecting them.

##### client/client.py
A resource server that validates access tokens issued by the authorization server and protects its endpoints.

##### client/client2.py
A resource server acting as a client of client1, interacting with its protected resources using OAuth tokens.
