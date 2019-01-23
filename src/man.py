import json
from socket import *
from blockchain import *
from ast import literal_eval

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
        self.man_pubkey = 'ghi'
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
        self.client_ids = 1

    # server and client exchange public keys
    def start(self):

        print("Listening...")

        self.mylogger.log(INFO, "Exchanging public Key with the Repo")
        msg = json.dumps({'man_pubk':self.man_pubkey, 'signature': 'oi'})
        sent = self.sock.sendto(str.encode(msg), (self.host, PORT_REPO))
        print("> repository pubkey received")
        data1, self.repo_address = self.sock.recvfrom(4096)
        self.mylogger.log(INFO, "Repo Pubkey received")

        self.mylogger.log(INFO, "Exchanging public Key with the Client")
        data2, client_addr = self.sock.recvfrom(4096)
        print("> client pubkey received")
        msg = json.dumps({'man_pubk': self.man_pubkey, 'client_id': '{}'.format(self.client_ids), 'signature': 'oi'})
        self.client_ids = self.client_ids+1
        sent = self.sock.sendto(str.encode(msg), client_addr)
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

    # manager waits for client or repository messages
    def loop(self):
        while (True):
            data, addr = self.sock.recvfrom(4096)
            data2 = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.repo_address):
                print("> client pubkey received")
                msg = json.dumps({'man_pubk': self.man_pubkey, 'client_id': self.client_ids, 'signature': 'oi'})
                self.client_ids = self.client_ids+1
                sent = self.sock.sendto(str.encode(msg), addr)
                self.address_client.append(addr)
                self.clients_pubkey.add(data2['c_pubk'])

            if 'auction' in data2:
                data2['signature'] = 'oi'
                data = json.dumps(data2)
                sent = self.sock.sendto(str.encode(data), self.repo_address)
                self.current_client = addr

            if 'ack' in data2 and 'info' in data2:
                print("> auction creation: OK")
                data2['signature'] = 'oi'
                data = json.dumps(data2)
                sent = self.sock.sendto(str.encode(data), self.current_client)

            if 'end' in data2:
                winner_dict = {}
                result = []

                print("> auction ended")

                # load the auction file and calculate the winner
                with open(data2['end']) as f:
                    lines = f.readlines()

                auction = lines.pop(0)
                auction_dict = literal_eval(auction)

                for line in lines:
                    line = line[:-1]
                    bid = literal_eval(line)
                    winner_dict[str(bid['id'])] = bid['amount']

                    # decrypt bids

                winner = max(zip(winner_dict.values(), winner_dict.keys()))

                auction_dict['winner'] = winner[1]
                auction_dict['winner_amount'] = winner[0]
                auction_dict['state'] = 'closed'

                result.append(str(auction_dict))

                for line in lines:
                    line = line[:-1]
                    result.append(line)

                with open(data2['end'], 'w') as f:
                    for line in result:
                        f.write("%s\n" % line)

                # the winner was found and the new blockchain was written to the file
                msg = json.dumps({'ack': 'ok'})
                sent = self.sock.sendto(str.encode(msg), self.repo_address)


if __name__ == "__main__":
    r = Manager(HOST, PORT)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")