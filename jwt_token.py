import os
import base64
import time
import uuid
import hashlib
import jwt
from Crypto.PublicKey import RSA


class JWTToken():
    "Generate Token"
    algorithm = 'RS256'

    def __init__(self, account, service, scope):
        self.account = account
        self.service = service
        self.scope = scope
        self.private_key = open(os.environ['PRIVATE_KEY_PATH']).read()

    def claim(self):
        return {
            "iss": os.environ['TOKEN_ISSUER'],
            "sub": self.account,
            "aud": self.service,
            "exp": int(time.time()) + (5 * 60),
            "nbf": int(time.time()),
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
            "access": [
                {
                    "type": "repository",
                    "name": "redis",
                    "actions": [
                        "push",
                        "pull"
                    ]
                }
            ]
        }

    def generate(self):
        "Generate JWT token"
        return jwt.encode(
            self.claim(), self.private_key, algorithm=self.algorithm,
            headers=self.headers()
        )

    def headers(self):
        "JWT header"
        return {
            'typ': 'JWT',
            'alg': self.algorithm,
            'kid': self.jwt_kid()
        }

    def jwt_kid(self):
        "Generates ID for signing key"
        key = RSA.importKey(self.private_key)
        der = key.publickey().exportKey("DER")
        payload = hashlib.sha256(der).digest()[:30]
        kid = base64.b32encode(payload)
        return ":".join([kid[i:i+4] for i in range(0, len(kid), 4)])
