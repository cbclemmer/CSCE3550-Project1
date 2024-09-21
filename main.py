import base64
import json
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

key_exp = 65537
key_size = 2048

expirationDays = 7
currentKeyId = 0

public_keys = { }
private_keys = { }

# Because python doesn't have an epoch time utility: https://stackoverflow.com/questions/29366914/what-is-python-equivalent-of-cs-system-datetime-ticks
def ticks(dt):
    return (dt - datetime(1, 1, 1)).total_seconds() * 10000000

def generate_rsa_pair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=key_exp,
        key_size=key_size,
        backend=default_backend()
    )

def get_expiration_date():
    current_date = datetime.now()
    future_date = current_date + timedelta(days=expirationDays)
    return future_date

def getHeader(kid: int):
    return {
        "alg": "RSA256",
        "typ": "JWT",
        "kid": kid
    }

def encode_json(data: object):
    return base64.urlsafe_b64encode(str.encode(json.dumps(data), 'utf-8')).decode('utf-8')

def get_JWT(add_expiry: bool = False):
    check_keys()
    public_key = list(public_keys.items())[0][1]
    kid = public_key["kid"]
    header = getHeader(kid)
    encoded_header = encode_json(header)
    payload = {
      "iat": ticks(datetime.now())
    }
    if add_expiry:
        payload["exp"] = ticks(get_expiration_date())
    encoded_payload = encode_json(payload)
    jwt = f'{encoded_header}.{encoded_payload}'
    signature = base64.urlsafe_b64encode(
        private_keys[kid].public_key().encrypt(
            str.encode(jwt, 'utf-8'), 
            padding.PKCS1v15()
        )
    ).decode('utf-8')
    return f'{encoded_header}.{encoded_payload}.{signature}'

def create_new_key():
    global currentKeyId
    global public_keys
    global private_keys
    currentKeyId += 1
    key = generate_rsa_pair()
    nums = key.public_key().public_numbers()
    public_keys[f'{currentKeyId}'] = {
        "kty": "RSA",
        "kid": f'{currentKeyId}',
        "use": "sig",
        "exp": ticks(get_expiration_date()),
        "alg": "RS256",
        "n": nums.n,
        "e": nums.e
    }
    private_keys[f'{currentKeyId}'] = key

def init():
    create_new_key()

def check_keys():
    now = ticks(datetime.now())
    for id in public_keys.keys():
        key = public_keys[id]
        if key["exp"] < now:
            del public_keys[id]
            del private_keys[id]
            create_new_key()

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/jwks.json':
            check_keys()
            self.send_response(200)
            self.send_header('Content-type', 'text/json')
            self.end_headers()
            key_list = { "keys": [data for _, data in public_keys.items()] }
            self.wfile.write(json.dumps(key_list).encode('utf-8'))

    def do_POST(self):
        if self.path == '/auth':
            token = get_JWT()
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(token.encode('utf-8'))

def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

init()
run_server(8080)