import json
from socket import *
from blockchain import *

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface

HOST = "127.0.0.1"
PORT = 8080
PORT_REPO = 8081

class Manager:
    def __init__(self, host, port):
        self.mylogger = LoggyLogglyMcface(name=Manager.__name__)
        self.mylogger.log(INFO, "Entering Manager interface")

        self.host = host
        self.port = port
        # public keys
        self.clients_pubkey = set()
        self.repo_pubkey = None
        self.man_pubkey = json.dumps({'man_pubk': 'ghi'})
        # list of addresses
        self.address_client = []
        self.repo_address = None
        # list of active and closed auctions
        self.active_auctions = []
        self.closed_auctions = []
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # current client being served
        self.current_client = None

    # Server and Client exchange Public Keys
    def start(self):

        print("Listening...")
        self.mylogger.log(INFO, "Exchanging public Key with the Repo")
        # send and receive public key (repo)
        sent = self.sock.sendto(str.encode(self.man_pubkey), (self.host, PORT_REPO))
        print("> repository pubkey received")
        data1, self.repo_address = self.sock.recvfrom(4096)
        self.mylogger.log(INFO, "Repo Pubkey received")

        self.mylogger.log(INFO, "Exchanging public Key with the Client")
        # send and receive public key (client)
        data2, client_addr = self.sock.recvfrom(4096)
        print("> client pubkey received")
        sent = self.sock.sendto(str.encode(self.man_pubkey), client_addr)
        self.address_client.append(client_addr)
        self.mylogger.log(INFO, "Client Pubkey received")

        # save public keys
        data1 = json.loads(data1)
        if 'repo_pubk' in data1:
            self.repo_pubkey = data1['repo_pubk']
        data2 = json.loads(data2)
        if 'c_pubk' in data2:
            self.clients_pubkey.add(data2['c_pubk'])

        self.mylogger.log(INFO, "Repo Pubkey : \n{:s}\nClient Pubkey : \n{:s}".format(data1['repo_pubk'],data2['c_pubk']))

        self.loop()

    # manager waits for client's messages
    def loop(self):
        while (True):
            data, addr = self.sock.recvfrom(4096)
            data2 = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.repo_address):
                print("> client pubkey received")
                sent = self.sock.sendto(str.encode(self.man_pubkey), addr)
                self.address_client.append(addr)

            if 'auction' in data2:
                sent = self.sock.sendto(data, self.repo_address)
                self.current_client = addr

            if 'ack' in data2:
                sent = self.sock.sendto(data, self.current_client)

if __name__ == "__main__":
    r = Manager(HOST, PORT)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")