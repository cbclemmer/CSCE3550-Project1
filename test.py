import json
import base64
import requests

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

print('Requesting key from /jwks.json')
res = requests.get('http://localhost:8080/jwks.json')
print(f'Result status code: {res.status_code}')

print('Key retrieved:')
key_data = json.loads(res.content.decode())
print(key_data)
exp = key_data["keys"][0]["e"]
mod = key_data["keys"][0]["n"]
print(f'\n\nExponent: {exp}')
print(f'Modulus: {mod}')

print('\n\nRecreating public key')
public_key = RSAPublicNumbers(exp, mod).public_key(default_backend())
print('Recreation successful!')

print('\n\nRequesting JWS from /auth')
res = requests.post('http://localhost:8080/auth')
print(f'Result status code: {res.status_code}')
parts = res.content.decode('utf-8').split('.')
test = "correct" if len(parts) == 3 else "incorrect"
print(f'Found {len(parts)} JWT parts, {test} amount!')

print(f'\n\nHeader b64: {parts[0]}')
header = json.loads(base64.urlsafe_b64decode(parts[0].encode('utf-8')))
print(f'Header Data: {header}')

body = json.loads(base64.urlsafe_b64decode(parts[1].encode('utf-8')))
print(f'\n\nBody b64: {parts[1]}')
print(f'Body Data: {body}')

signature = base64.urlsafe_b64decode(parts[2].encode('utf-8'))
print(f'\n\nSignature: {parts[2]}')
try:
    public_key.verify(
        signature,
        f'{parts[0]}.{parts[1]}'.encode(),
        padding.PKCS1v15(),
        algorithm=hashes.SHA256()
    )
    print(f'Signature verified successfully')
except:
    print('Signature verification failed')
