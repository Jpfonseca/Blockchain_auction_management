import json
from socket import *
import sys

class Repository():
    def __init__(self, host, port):
        self.host = host
        self.port = port

    #Server and Client exchange Public Keys
    def start(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)

        #print('Listening on: host {} and port {}'.format(*server_add))
        print('Listening on: host {} and port {}'.format(self.host,self.port))
        self.sock.bind((self.host, self.port))

        while True:
            print('Waiting for message...')
            data, address = self.sock.recvfrom(4096)

            #print('received {} bytes from {}'.format(len(data), address))
            print(data)

            msg = "Server's public key"
            if data:
                msg = json.dumps({'repo_PK': 'abcdefgh'})
                sent = self.sock.sendto(str.encode(msg), address)
                #print('sent {} bytes back to {}'.format(sent, address))

    def close(self):
        self.sock.close()

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    r = Repository(host, port)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
        r.close()