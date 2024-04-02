import os
import json
import urllib.request
import urllib.parse

# Configurações do Keycloak
KEYCLOAK_URL = os.getenv('KEYCLOAK_BASE_URL')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM_NAME')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')

def lambda_handler(event, context):
    # print("Event received:", event)  # Log do evento recebido
    
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        # print("Failed to decode JSON body")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Bad Request', 'error_description': 'Invalid JSON format'})
        }
    
    # Extrai o token de refresh da solicitação recebida
    refresh_token = body.get("RefreshToken")
    if not refresh_token:
        # print("Missing refresh token")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Bad Request', 'error_description': 'Missing refresh token'})
        }
    
    # Faz a solicitação ao Keycloak para renovar o token de acesso
    token_data = get_keycloak_refresh_token(refresh_token)
    if not token_data:
        # print("Failed to refresh access token from Keycloak")
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Unauthorized', 'error_description': 'Failed to refresh access token'})
        }

    # print("Access token refreshed from Keycloak:", token_data)  # Log do token de acesso renovado

    # Retorna a resposta com o token de acesso renovado
    return {
        'statusCode': 200,
        'body': json.dumps(token_data)
    }

def get_keycloak_refresh_token(refresh_token):
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    data = urllib.parse.urlencode(payload).encode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    req = urllib.request.Request(token_url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read()
            # print("Keycloak response:", response_body.decode())  # Log da resposta do Keycloak
            return json.loads(response_body.decode())
    except urllib.error.URLError as e:
        # print(f"Error reaching out to Keycloak: {e.reason}")
        return None
