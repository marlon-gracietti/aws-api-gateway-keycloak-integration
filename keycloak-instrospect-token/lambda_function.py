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
    auth_header = event.get("authorizationToken")
    if not auth_header or not auth_header.startswith("Bearer "):
        return generate_policy(None, "Deny", event["methodArn"])
    
    access_token = auth_header.split(" ")[1]
    token_valid = introspect_token(access_token)
    
    if token_valid:
        # Decodifica o token para extrair 'custom:cnpj' sem adicionar funções adicionais
        # O token JWT é base64url encoded, então decodifique a parte do payload para obter as claims
        split_token = access_token.split('.')
        payload = split_token[1]
        payload += '=' * (4 - len(payload) % 4)  # Padding para base64
        decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')
        claims = json.loads(decoded_payload)
        cnpj = claims.get('custom:cnpj')
        
        if cnpj:
            # Inclui 'custom:cnpj' no contexto da política
            return generate_policy('user', "Allow", event["methodArn"], {'customCNPJ': cnpj})
        else:
            print("CNPJ not found in token claims.")
            return generate_policy(None, "Deny", event["methodArn"])
    else:
        return generate_policy(None, "Deny", event["methodArn"])

def introspect_token(token):
    introspection_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    payload = {"client_id": KEYCLOAK_CLIENT_ID, "client_secret": KEYCLOAK_CLIENT_SECRET, "token": token}
    data = urllib.parse.urlencode(payload).encode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    req = urllib.request.Request(introspection_url, data=data, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            introspection_response = json.loads(response.read().decode())
            return introspection_response.get("active", False)
    except urllib.error.URLError as e:
        print(f"Error during token introspection: {e.reason}")
        return False

def generate_policy(principal_id, effect, resource, context={}):
    auth_response = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource,
            }],
        },
        'context': context
    }
    return auth_response
