import Crypto

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Module(object):
    def __init__(self):
        pass

    def handle_message(self,message:bytearray):
        pass

    def finish(self):
        pass


class Authenticator(Module):
    def __init__(self):
        super().__init__(self)

test_key = RSA.generate(2048)
test_message = bytes("I'm encrypted!",'utf-8')
cipher = PKCS1_OAEP.new(test_key.publickey())
encrypted_message = cipher.encrypt(test_message)

dec_cipher = PKCS1_OAEP.new(test_key)
dec_message = dec_cipher.decrypt(encrypted_message)

print(encrypted_message)
print(dec_message)
