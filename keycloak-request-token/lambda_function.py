import base64
import json
import urllib.request
import urllib.parse
import boto3

ssm = boto3.client('ssm')

def get_parameter(name, with_decryption=False):    
    response = ssm.get_parameter(Name=name, WithDecryption=with_decryption)
    return response['Parameter']['Value']

# Configurações do Keycloak
# KEYCLOAK_URL = os.getenv('KEYCLOAK_BASE_URL')
# KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM_NAME')
# KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID')
# KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')

KEYCLOAK_URL = get_parameter('/keycloak/nhub/base_url')
KEYCLOAK_REALM = get_parameter('/keycloak/nhub/realm_name')
KEYCLOAK_CLIENT_ID = get_parameter('/keycloak/nhub/client_id')
KEYCLOAK_CLIENT_SECRET = get_parameter('/keycloak/nhub/client_secret', with_decryption=True)

def lambda_handler(event, context):
    # print("Event received:", event)  # Log do evento recebido

    # Extrai o cabeçalho de autorização da solicitação recebida
    auth_header = event.get("headers", {}).get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        # print("Missing or invalid Authorization header")
        return {
            'statusCode': 403,            
            'body': json.dumps({
                'Message': 'User is not authorized to access this resource with an explicit deny'
            })            
        }
    
    # print("Authorization header found:", auth_header)  # Log do cabeçalho de autorização

    # Decodifica o token Basic para obter username e password
    auth_header_encoded = auth_header.split(" ")[1]
    auth_header_decoded = base64.b64decode(auth_header_encoded).decode('utf-8')
    username, password = auth_header_decoded.split(":")
    # print(f"Decoded credentials - Username: {username}, Password: {password}")  # Log das credenciais decodificadas

    # Faz a solicitação ao Keycloak para obter o token de acesso
    token_data = get_keycloak_access_token(username, password)
    if not token_data:
        # print("Failed to obtain access token from Keycloak")
        return {
            'statusCode': 403,            
            'body': json.dumps({
                'Message': 'User is not authorized to access this resource with an explicit deny'
            })            
        }

    # print("Access token obtained from Keycloak:", token_data)

    # Mudar a estrutura da resposta para manter o padrão do Cognito
    cognito_compatible_response = {
        'AccessToken': token_data.get('access_token'),
        'ExpiresIn': token_data.get('expires_in'),
        'RefreshExpiresIn': token_data.get('refresh_expires_in'),
        'RefreshToken': token_data.get('refresh_token'),
        'TokenType': token_data.get('token_type'),
        'IdToken': token_data.get('id_token'),       
        'NotBeforePolicy': token_data.get('not-before-policy'),       
        'SessionState': token_data.get('session_state'),       
        'Scope': token_data.get('scope')               
    }

    # Retorna a resposta com o token de acesso
    return {
        'statusCode': 200,
        'body': json.dumps(cognito_compatible_response)
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
        # print(f"Error reaching out to Keycloak: {e.reason}")
        return None
