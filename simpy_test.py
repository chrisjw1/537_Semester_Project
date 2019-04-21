import simpy
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json


class network_module(object):
    def __init__(self,env:simpy.Environment):
        self.env = env
        self.pending_messages = []

    def on_start(self):
        pass

    def run(self):
        self.on_start()
        while True:
            if self.has_message():
                self.handle_message(self.get_message())
            yield self.env.timeout(0.05)

    def has_message(self):
        return len(self.pending_messages) > 0

    def get_message(self):
        return self.pending_messages.pop()

    def handle_message(self,message:bytearray):
        pass

    def send(self,message:bytearray,recieve_buffer:list):
        # yield self.env.timeout(0.05)
        recieve_buffer.append(message)

class tic(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env)
        self.toc_buffer = None

    def set_toc(self,toc:network_module):
        self.toc_buffer = toc.pending_messages

    def on_start(self):
        self.send(bytearray([1,2,3,4]),self.toc_buffer)
        print("tic start")

    def handle_message(self,message:bytearray):
        self.send(message,self.toc_buffer)
        print(str(message)+" sent to toc")

class toc(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env)
        self.tic_buffer = None

    def set_tic(self,tic:network_module):
        self.tic_buffer = tic.pending_messages

    def handle_message(self,message:bytearray):
        self.send(message,self.tic_buffer)
        print(str(message)+" sent to tic")

class authenticator(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env)
        self.pacemaker_buffer = None

    def set_pacemaker(self,pacemaker:network_module):
        self.pacemaker_buffer = pacemaker.pending_messages

    def handle_message(self,message:bytearray):
        # TODO possibly simulate entire BLE packet
        data_field = message

class pacemaker(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env)
        self.private_key = RSA.generate(2048)
        self.auth_buffer = None
        self.auth_public_key = None
        self.programmer_buffer = None
        self.programmer_public_key = None

    def handle_message(self,message:bytearray):
        dec_cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_message = dec_cipher.decrypt(message)
        parsed_message = json.loads(str(decrypted_message,encoding='utf-8'))
        print(message)
        print(parsed_message)

    def set_programmer(self,programmer:network_module):
        self.programmer_buffer = programmer.pending_messages
        programmer.pacemaker_public_key = self.private_key.publickey()

    def decrypt_message(self,encrypted_message:bytearray):
        decrypt_cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_message = decrypt_cipher.decrypt(encrypted_message)
        message_dict = json.loads(str(decrypted_message,'utf-8'))
        if message_dict['type'] == 'op_request':
            verify_cipher = PKCS1_OAEP.new(self.programmer_public_key)
        elif message_dict['type'] == 'auth_response':
            verify_cipher =  PKCS1_OAEP.new(self.auth_public_key)
        else:
            return {'type':'error'}
        if verify_cipher.verify(message_dict['signature']):
            return message_dict
        else:
            return {'type':'error'}


class programmer(network_module):
    def __init__(self,env:simpy.Environment,test_mode="Standard OP"):
        super().__init__(env)
        self.pacemaker_buffer = None
        self.pacemaker_public_key = None
        self.backend_buffer = None
        self.backend_public_key = None
        self.test_mode = test_mode
        self.private_key = RSA.generate(2048)

    def set_pacemaker(self,pacemaker:pacemaker):
        self.pacemaker_buffer = pacemaker.pending_messages
        pacemaker.programmer_public_key = self.private_key.publickey()

    def set_backend(self,backend:network_module):
        self.backend_buffer = backend.pending_messages


    def on_start(self):
        if self.test_mode == "Standard OP":
            json_message = {'op_name':'STANDARD OP'}
            to_send = bytearray(json.dumps(json_message),"utf-8")
            to_send = PKCS1_OAEP.new(self.pacemaker_public_key).encrypt(to_send)
            self.send(to_send,self.pacemaker_buffer)

    def create_op_request_message(self):
        message_dict = {'type':'op_request','time':self.env.now}
        sign_cipher = PKCS1_OAEP.new(self.private_key)
        hash = SHA256.new()
        hash.update(message_dict['time'])
        message_dict['signature'] = sign_cipher.sign(hash)
        unencrypted_message_bytes = bytearray(json.dumps(message_dict),'utf-8')
        encrypt_cipher = PKCS1_OAEP.new(self.pacemaker_public_key)
        encrypted_message_bytes = encrypt_cipher.encrypt(unencrypted_message_bytes)
        return encrypted_message_bytes

    def handle_message(self,message:bytearray):
        # TODO implement encryption
        dec_cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_message = dec_cipher.decrypt(message)
        parsed_message = json.loads(str(decrypted_message,encoding='utf-8'))


class backend(network_module):
    def __init__(self,env:simpy.Environment):
        super().__init__(env)
        self.programmer_buffer = None
        self.programmer_public_key = None
        self.private_key = RSA.generate(2048)


    def set_programmer(self,programmer:programmer):
        self.programmer_buffer = programmer.pending_messages
        programmer.backend_public_key = self.private_key.publickey()


env = simpy.Environment()
# n1 = tic(env)
# n2 = toc(env)
# n1.set_toc(n2)
# n2.set_tic(n1)
# env.process(n1.run())
# env.process(n2.run())
pm = pacemaker(env)
prg = programmer(env)
prg.set_pacemaker(pm)
pm.set_programmer(prg)
env.process(pm.run())
env.process(prg.run())
env.run(until=0.5)
# env.run(until=10)