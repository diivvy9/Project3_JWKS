#Divya DArji
#CSCE 3550 Project 3
#ddd0239

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

NOT_MY_KEY = b'ylcg3o6pv84aehqj'  # byte string to use for AES encryption and decryption


# Define functions
def int_to_base64(value):  # Convert an integer to a Base64URL-encoded string
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def encrypt_with_aes(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add PKCS7 padding to the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def decrypt_with_aes(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext


def serialize_key_to_pem(key):  # Serialize the private key to PKCS1 PEM format
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


def deserialize_pem_to_key(pem_bytes):  # Deserialize the private key from PKCS1 PEM format
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None
    )


def get_all_valid_private_keys_with_kid() -> list[tuple[int, RSAPrivateKey]]:  # Get all valid keys from the DB
    current_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn1:
        cursor = conn1.execute(query, (current_time,))
        key_data = cursor.fetchall()

    # Deserialize the keys and pair with their respective kid
    keys = [(data[0], deserialize_pem_to_key(decrypt_with_aes(NOT_MY_KEY, data[1]))) for data in key_data]
    return keys


def get_private_key_with_kid_from_db(expired=False):  # Get un/expired key from DB
    current_time = int(datetime.datetime.utcnow().timestamp())

    # Query to fetch based on expiration status
    if expired:
        query = "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
    else:
        query = "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn2:
        cursor = conn2.execute(query, (current_time,))
        key_data = cursor.fetchone()

    # Deserialize the key and pair with its kid if found
    if key_data:
        return key_data[0], deserialize_pem_to_key(decrypt_with_aes(NOT_MY_KEY, key_data[1]))
    return None, None


def get_user_id_from_username(username):  # Get user_id given a username from the database
    with sqlite3.connect('totally_not_my_privateKeys.db') as connGetID:
        cursor = connGetID.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

    if user_data:
        return user_data[0]
    return None


# Create and initialize DB
conn = sqlite3.connect('totally_not_my_privateKeys.db')  # Create DB

conn.execute('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, '
             'key BLOB NOT NULL, exp INTEGER NOT NULL)')  # Create keys table in DB

conn.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, '
             'password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, '
             'last_login TIMESTAMP)')  # Create users table in DB

conn.execute('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, '
             'request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, '
             'FOREIGN KEY(user_id) REFERENCES users(id));')  # Create auth_logs table in DB

conn.commit()  # Commit the above changed to the DB

# Create and serialize keys
init_unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Create RSA key
init_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_unexpired_key_PEM = serialize_key_to_pem(init_unexpired_key)  # Serialize key to PEM format
init_expired_key_PEM = serialize_key_to_pem(init_expired_key)

now = int(datetime.datetime.utcnow().timestamp())  # Get current time
hour_from_now = now + 3600  # Get one hour from now time

# Insert the serialized and encrypted keys into the DB
encrypted_unexpired_key = encrypt_with_aes(NOT_MY_KEY, init_unexpired_key_PEM.encode('utf-8'))
encrypted_expired_key = encrypt_with_aes(NOT_MY_KEY, init_expired_key_PEM.encode('utf-8'))

conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_unexpired_key, hour_from_now))
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_expired_key, (now - 36000)))
conn.commit()

hostName = "localhost"  # Use localhost for server
serverPort = 8080  # Use port 8080 for server

class RateLimiter:
    def __init__(self, max_requests, per_seconds):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.request_times = {}

    def allow_request(self, ip):
        current_time = time.time()
        if ip not in self.request_times:
            self.request_times[ip] = [current_time]
            return True
        else:
            # Filter out old timestamps
            self.request_times[ip] = [t for t in self.request_times[ip] if current_time - t < self.per_seconds]
            if len(self.request_times[ip]) < self.max_requests:
                self.request_times[ip].append(current_time)
                return True
            else:
                return False


rate_limiter = RateLimiter(max_requests=10, per_seconds=1)

# Configure web server requests/actions
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):  # Define PUT request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_PATCH(self):  # Define PATCH request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_DELETE(self):  # Define DELETE request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_HEAD(self):  # # Define HEAD request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            client_ip = self.client_address[0]

            # Check with the rate limiter
            if not rate_limiter.allow_request(client_ip):
                self.send_response(429, "Too Many Requests")
                self.end_headers()
                return
            
            # Send a test 200 response if rate limiting is not triggered
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes("Test response", "utf-8"))
                return

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            auth_data = json.loads(post_data.decode('utf-8'))

            # Authentication logic
            kid, key = get_private_key_with_kid_from_db('expired' in params)

            if not key:
                self.send_response(500, "Unable to fetch private key")
                self.end_headers()
                return

            headers = {"kid": str(kid)}
            token_payload = {"user": auth_data.get('username'),
                            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            key_pem = serialize_key_to_pem(key)
            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

            # Log the successful request
            print(f"Logging /auth request for IP: {client_ip}")
            user_id = get_user_id_from_username(auth_data.get('username'))
            request_ip = self.client_address[0]
            request_timestamp = datetime.datetime.utcnow()

            try:
                with sqlite3.connect('totally_not_my_privateKeys.db') as connLog:
                    connLog.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                                    (request_ip, request_timestamp, user_id))
                    connLog.commit()
            except sqlite3.Error as e:
                print(f"Error logging /auth request: {e}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return


    


        elif parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            # Generate a secure password using UUIDv4
            generated_password = str(uuid.uuid4())

            # Hash the password using Argon2
            ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
            hashed_password = ph.hash(generated_password)

            # Store the user details and hashed password in the users table
            with sqlite3.connect('totally_not_my_privateKeys.db') as connRegister:
                connRegister.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                                     (user_data['username'], user_data['email'], hashed_password))
                connRegister.commit()

            # Return the generated password to the user
            response_data = {"password": generated_password}
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

        else:
            self.send_response(405)
            self.end_headers()
            return

    def do_GET(self):  # Define GET request action
        if self.path == "/.well-known/jwks.json":  # Check if requested path is correct
            valid_keys_with_kid = get_all_valid_private_keys_with_kid()
            jwks = {"keys": []}
            # Create list of keys
            for kid, key in valid_keys_with_kid:
                private_numbers = key.private_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(private_numbers.public_numbers.n),
                    "e": int_to_base64(private_numbers.public_numbers.e)
                })
            # Return list of keys
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)  # Define web server
    
    print("HTTP Server running on Localhost port 8080...")  # Print message indicating server start

    try:
        webServer.serve_forever()  # Start web server
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()  # Close web server
        print("Server stopped.")  # Optional: Print message indicating server stop
