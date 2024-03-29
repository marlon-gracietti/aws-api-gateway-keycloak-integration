import os
import base64
import json
import urllib.request
import urllib.parse

# Configurações do Keycloak
KEYCLOAK_URL = os.getenv('KEYCLOAK_BASE_URL')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM_NAME')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')

def lambda_handler(event, context):
    print("Event received:", event)  # Log do evento recebido

    # Extrai o cabeçalho de autorização da solicitação recebida
    auth_header = event.get("headers", {}).get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        print("Missing or invalid Authorization header")
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Unauthorized', 'error_description': 'Missing or invalid Authorization header'})
        }
    
    print("Authorization header found:", auth_header)  # Log do cabeçalho de autorização

    # Decodifica o token Basic para obter username e password
    auth_header_encoded = auth_header.split(" ")[1]
    auth_header_decoded = base64.b64decode(auth_header_encoded).decode('utf-8')
    username, password = auth_header_decoded.split(":")
    print(f"Decoded credentials - Username: {username}, Password: {password}")  # Log das credenciais decodificadas

    # Faz a solicitação ao Keycloak para obter o token de acesso
    token_data = get_keycloak_access_token(username, password)
    if not token_data:
        print("Failed to obtain access token from Keycloak")
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Unauthorized', 'error_description': 'Failed to obtain access token from Keycloak'})
        }

    print("Access token obtained from Keycloak:", token_data)  # Log do token de acesso obtido

    # Retorna a resposta com o token de acesso
    return {
        'statusCode': 200,
        'body': json.dumps(token_data)
    }

def get_keycloak_access_token(username, password):
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "username": username,
        "password": password,
        "grant_type": "password",
        "scope": "openid"
    }
    data = urllib.parse.urlencode(payload).encode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    req = urllib.request.Request(token_url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read()
            print("Keycloak response:", response_body.decode())  # Log da resposta do Keycloak
            return json.loads(response_body.decode())
    except urllib.error.URLError as e:
        print(f"Error reaching out to Keycloak: {e.reason}")
        return None
