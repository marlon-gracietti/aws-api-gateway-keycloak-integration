import os
import json
import urllib.request
import urllib.parse
import base64

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
        # Decodifica o token para extrair custom:cnpj
        claims = decode_jwt(access_token)
        cnpj = claims.get("custom:cnpj", None)
        if cnpj:
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

def decode_jwt(token):
    # Extrai apenas o payload do JWT
    payload_base64 = token.split('.')[1]
    padding = len(payload_base64) % 4
    if padding > 0:
        payload_base64 += '=' * (4 - padding)
    decoded_payload = base64.urlsafe_b64decode(payload_base64).decode('utf-8')
    return json.loads(decoded_payload)

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
