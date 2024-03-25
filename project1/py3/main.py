from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3


# Initialize Database 
conn = sqlite3.connect('totally_not_my_privateKeys.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS keys (
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL, 
    exp INTEGER NOT NULL
)''')

conn.commit()


hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def rsa_to_pem(public_key):
        pem = public_key.public_bytes(encoding = serialization.Encoding.PEM,
         format = serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem.decode('utf-8')
    
def pem_to_rsa(pem_string):
    public_key = serialization.load_pem_public_key(pem_string.encode('utf-8'),backend = default_backend())
    return public_key
    

class MyServer(BaseHTTPRequestHandler):
    
    #Saves a key to the db 
    def write_to_db(self,key,exp):
        try:
            payload = rsa_to_pem(key)
            c.execute("INSERT INTO keys (key,exp) VALUES (?,?)", (payload,exp))
            conn.commit()
            return True
        except sqlite3.Error as e: 
            print("Could not save key to DB.")
            return False
    
    #Retrieve a key from the database
    def get_key(self, kid):
        try:
            c.execute("SELECT key, exp FROM keys WHERE kid=?",(kid,))
            payload = c.fetchone()
            if payload: 
                key_string = payload[0] # Save the key PEM string to a variable
                exp = payload[1]   #Save the expired value to a variable  
                rsa_key = pem_to_rsa(key_string) # Conver PEM string back to RSA key
                return rsa_key,exp
            else: 
                return None, None
        except sqlite3.Error as e: 
            print("Could not retrieve key from DB.")
            return None, None

        
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)

            #Write the key to the DB 
            self.write_to_db(private_key,token_payload["exp"])

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            #Get key from database
            key,exp = self.get_key("goodKID")

            if key and exp: 
                numbers = key.public_key().public_numbers()
                keys = {
                    "keys": [
                        {
                            "alg": "RS256",
                            "kty": "RSA",
                            "use": "sig",
                            "kid": "goodKID",
                            "n": int_to_base64(numbers.public_numbers.n),
                            "e": int_to_base64(numbers.public_numbers.e),
                        }
                    ]
                }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return



    
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
