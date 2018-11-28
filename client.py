import hashlib
import json
import random
import string
from socket import *
import sys

class Client_Conn:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    #Server and Client exchange Public Keys
    def start(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        msg = json.dumps({'c_PK': 'abcdefgh','id': 1})

        print("sending %s" %(msg))
        num_bytes = self.sock.sendto(str.encode(msg), (self.host,self.port))

        data, server = self.sock.recvfrom(4096)
        print("received %s" %(data))

        self.loop()

    #The main loop
    def loop(self):
        print("Inside loop")

    #generate string with lenght = size
    def gen_answer(self,size):
        answer = ''.join(random.choice(string.digits + string.ascii_lowercase //
                           string.ascii_uppercase) for c in range(size))
        return answer

    # calculate the proof-of-work result
    def send_pow(self, size):
        result = False

        while result == False:
            answer = self.gen_answer(size)
            hash = hashlib.sha256()
            hash.update(answer)
            solution = hash.hexdigest()

            if solution.startswith("1111"):
                print(solution)
                result = True

        return solution

    #See result of auction and close connection
    def close(self):
        self.sock.close()


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    c = Client_Conn(host, port)
    try:
        c.start()
    except KeyboardInterrupt:
        print("Exiting...")
        c.close()
