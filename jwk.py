from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

# This constant is for AES encryption/decryption
SECRET_KEY = b'ylcg3o6pv84aehqj'


# Utility functions
def base64_encode_integer(integer_value):  # Convert integer to Base64URL-encoded string
    hex_value = format(integer_value, 'x')
    # Ensure hex_value has even length
    if len(hex_value) % 2 == 1:
        hex_value = '0' + hex_value
    byte_value = bytes.fromhex(hex_value)
    base64_encoded = base64.urlsafe_b64encode(byte_value).rstrip(b'=')
    return base64_encoded.decode('utf-8')


def aes_encrypt(key: bytes, data: bytes) -> bytes:
    aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()

    # Pad data according to PKCS7
    data_padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = data_padder.update(data) + data_padder.finalize()

    # Encrypt and return
    encrypted_data = aes_encryptor.update(padded_data) + aes_encryptor.finalize()
    return encrypted_data


def aes_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    aes_cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()

    # Decrypt to padded data
    decrypted_padded_data = aes_decryptor.update(encrypted_data) + aes_decryptor.finalize()

    # Unpad and return
    data_unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = data_unpadder.update(decrypted_padded_data) + data_unpadder.finalize()
    return decrypted_data


def pem_serialize_private_key(private_key):  # Convert private key to PEM format
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


def pem_deserialize_private_key(pem_data):  # Convert PEM format back to private key
    return serialization.load_pem_private_key(
        pem_data,
        password=None
    )


def fetch_valid_keys_with_kid() -> list[tuple[int, RSAPrivateKey]]:  # Retrieve valid RSA keys and their kids from database
    present_time = int(datetime.datetime.utcnow().timestamp())
    select_query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect('totally_not_my_privateKeys.db') as connection:
        cursor = connection.execute(select_query, (present_time,))
        keys_info = cursor.fetchall()

    keys = [(info[0], pem_deserialize_private_key(aes_decrypt(SECRET_KEY, info[1]))) for info in keys_info]
    return keys


def fetch_specific_private_key_with_kid(expired=False):  # Obtain a specific RSA key from database, expired or not
    present_time = int(datetime.datetime.utcnow().timestamp())

    if expired:
        select_query = "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
    else:
        select_query = "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"

    with sqlite3.connect('totally_not_my_privateKeys.db') as connection:
        cursor = connection.execute(select_query, (present_time,))
        key_info = cursor.fetchone()

    if key_info:
        return key_info[0], pem_deserialize_private_key(aes_decrypt(SECRET_KEY, key_info[1]))
    return None, None


def fetch_user_id_by_username(username):  # Retrieve user ID for a given username
    with sqlite3.connect('totally_not_my_privateKeys.db') as connection:
        cursor = connection.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_info = cursor.fetchone()

    return user_info[0] if user_info else None


# Database setup
db_conn = sqlite3.connect('totally_not_my_privateKeys.db')  # Initialize database connection

# Create tables if they don't already exist
db_conn.execute('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)')
db_conn.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)')
db_conn.execute('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))')

db_conn.commit()  # Commit the table creation

# Generate and store RSA keys
new_unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Generate new RSA key
new_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
unexpired_key_pem = pem_serialize_private_key(new_unexpired_key)
expired_key_pem = pem_serialize_private_key(new_expired_key)

current_time = int(datetime.datetime.utcnow().timestamp())
future_time = current_time + 3600  # One hour in the future

# Encrypt and insert keys into the database
db_conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (aes_encrypt(SECRET_KEY, unexpired_key_pem.encode('utf-8')), future_time))
db_conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (aes_encrypt(SECRET_KEY, expired_key_pem.encode('utf-8')), (current_time - 36000)))
db_conn.commit()

server_address = "localhost"  # Server will run on localhost
server_port = 8080  # Server will use port 8080

class RequestRateLimiter:
    def __init__(self, max_requests, period_seconds):
        self.max_requests = max_requests
        self.period_seconds = period_seconds
        self.requests_log = {}

    def is_request_allowed(self, ip_address):
        current_timestamp = time.time()
        if ip_address not in self.requests_log:
            self.requests_log[ip_address] = [current_timestamp]
            return True
        self.requests_log[ip_address] = [timestamp for timestamp in self.requests_log[ip_address] if current_timestamp - timestamp < self.period_seconds]
        if len(self.requests_log[ip_address]) < self.max_requests:
            self.requests_log[ip_address].append(current_timestamp)
            return True
        return False

rate_limiter = RequestRateLimiter(max_requests=10, per_seconds=1)

# Web server request handling
class ServerHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        request_path = urlparse(self.path)
        query_parameters = parse_qs(request_path.query)

        if request_path.path == "/auth":
            requesting_ip = self.client_address[0]

            if not rate_limiter.is_request_allowed(requesting_ip):
                self.send_response(429, "Too Many Requests")
                self.end_headers()
                return
            
            content_length = int(self.headers['Content-Length'])
            post_body = self.rfile.read(content_length)
            auth_details = json.loads(post_body.decode('utf-8'))

            key_id, private_key = fetch_specific_private_key_with_kid('expired' in query_parameters)

            if not private_key:
                self.send_response(500, "Private key retrieval failed")
                self.end_headers()
                return

            jwt_headers = {"kid": str(key_id)}
            jwt_payload = {"user": auth_details.get('username'), "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            private_key_pem = pem_serialize_private_key(private_key)
            jwt_token = jwt.encode(jwt_payload, private_key_pem, algorithm="RS256", headers=jwt_headers)

            user_id = fetch_user_id_by_username(auth_details.get('username'))
            log_request(requesting_ip, user_id)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(jwt_token, "utf-8"))
            return

        elif request_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_body = self.rfile.read(content_length)
            registration_data = json.loads(post_body.decode('utf-8'))

            new_password = str(uuid.uuid4())
            password_hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
            password_hash = password_hasher.hash(new_password)

            with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
                conn.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (registration_data['username'], registration_data['email'], password_hash))
                conn.commit()

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"password": new_password}), "utf-8"))

        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            keys_with_kid = fetch_valid_keys_with_kid()
            jwks_dict = {"keys": []}
            for kid, key in keys_with_kid:
                public_numbers = key.private_numbers().public_numbers
                jwks_dict["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": base64_encode_integer(public_numbers.n),
                    "e": base64_encode_integer(public_numbers.e)
                })
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks_dict), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()


def log_request(ip, user_id):
    print(f"Logging /auth request from IP: {ip}")
    with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
        conn.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)", (ip, datetime.datetime.utcnow(), user_id))
        conn.commit()


if __name__ == "__main__":
    http_server = HTTPServer((server_address, server_port), ServerHandler)
    print("Server started at http://localhost:8080")

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http_server.server_close()
        print("Server shut down.")
