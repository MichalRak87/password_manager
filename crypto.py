import hashlib
from cryptography.fernet import Fernet
from base64 import b64encode

class Crypto:
    def __init__(self, pin: str):
        pin = Crypto.prepare_pin(pin)
        self.fernet = Fernet(pin)

    @staticmethod
    def prepare_pin(pin):
        token = hashlib.md5(pin.encode('utf-8')).hexdigest()
        token = b64encode(token.encode('utf-8'))
        return token

    def encrypt(self, string):
        return self.fernet.encrypt(string.encode('utf-8'))

    def decrypt(self, string):
        return self.fernet.decrypt(string).decode('utf-8')

