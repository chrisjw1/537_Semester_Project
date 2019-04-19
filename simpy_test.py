import simpy

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

env = simpy.Environment()
n1 = tic(env)
n2 = toc(env)
n1.set_toc(n2)
n2.set_tic(n1)
env.process(n1.run())
env.process(n2.run())
env.run(until=5)
env.run(until=10)