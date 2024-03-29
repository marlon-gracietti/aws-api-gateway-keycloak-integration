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
    # Extrai o token de autorização da solicitação recebida
    auth_header = event.get("authorizationToken")
    if not auth_header or not auth_header.startswith("Bearer "):
        return generate_policy(None, "Deny", event["methodArn"])

    # Extrai o token de acesso do cabeçalho de autorização
    access_token = auth_header.split(" ")[1]

    # Introspecta o token de acesso no Keycloak
    token_valid = introspect_token(access_token)
    if token_valid:
        # Substitua 'user' pelo identificador do usuário obtido do token, se necessário
        return generate_policy('user', "Allow", event["methodArn"])
    else:
        return generate_policy(None, "Deny", event["methodArn"])

def introspect_token(token):
    introspection_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    payload = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "token": token
    }
    data = urllib.parse.urlencode(payload).encode()
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    req = urllib.request.Request(introspection_url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read()
            introspection_response = json.loads(response_body.decode())
            # Verifica se o token está ativo
            return introspection_response.get("active", False)
    except urllib.error.URLError as e:
        print(f"Error during token introspection: {e.reason}")
        return False

def generate_policy(principal_id, effect, resource):
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
    }
    return auth_response
