import json
from socket import *
from blockchain import *

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface

HOST = "127.0.0.1"
PORT_MAN = 8080
PORT_REPO = 8081

class Repository():
    def __init__(self, host, port):
        self.mylogger = LoggyLogglyMcface(name=Repository.__name__)
        self.mylogger.log(INFO, "Entering Repository interface")

        self.host = host
        self.port = port
        # public keys
        self.clients_pubkey = set()
        self.repo_pubkey = json.dumps({'repo_pubk': 'abc'})
        self.man_pubkey = None
        # list of the addresses
        self.address_client = []
        self.manager_address = None
        # list of active and closed auctions
        self.active_auctions = []
        self.closed_auctions = []
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # incremental serial number
        self.serial = 0

    # Server and Client exchange Public Keys
    def start(self):

        print("Listening...")

        self.mylogger.log(INFO, "Exchanging public Key with the Manager")
        # send and receive public key (manager)
        data1, self.manager_address = self.sock.recvfrom(4096)
        print("> manager pubkey received")
        sent = self.sock.sendto(str.encode(self.repo_pubkey), self.manager_address)
        self.mylogger.log(INFO, "Manager Pubkey received")

        self.mylogger.log(INFO, "Exchanging public Key with the Client")
        # send and receive public key (client)
        data2, client_addr = self.sock.recvfrom(4096)
        print("> client pubkey received")
        sent = self.sock.sendto(str.encode(self.repo_pubkey), client_addr)
        self.address_client.append(client_addr)
        self.mylogger.log(INFO, "Client Pubkey received")

        # save public keys
        data1 = json.loads(data1)
        if 'man_pubk' in data1:
            self.man_pubkey = data1['man_pubk']
        data2 = json.loads(data2)
        if 'c_pubk' in data2:
            self.clients_pubkey.add(data2['c_pubk'])
        self.mylogger.log(INFO, "Repo Pubkey : \n{:s}\nClient Pubkey : \n{:s}".format(data1['man_pubk'],data2['c_pubk']))

        self.loop()

    # function that waits for messages of clients
    def loop(self):
        while (True):

            ###to do: check if time limit of auctions has surpassed
            ###if one has ended, send message to all clients and ask the bidder to reveal identities

            data, addr = self.sock.recvfrom(4096)
            data = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.manager_address):
                print("> client pubkey received")
                sent = self.sock.sendto(str.encode(self.repo_pubkey), addr)
                self.address_client.append(addr)

            # auction message is received
            if 'auction' in data:
                if ('bidders' in data['auction']) and ('limit_bids' in data['auction']):
                    self.create_auction(addr, self.serial + 1, data['auction']['name'], data['auction']['time-limit'],
                                        data['auction']['description'], data['auction']['type'],
                                        bidders=data['auction']['bidders'], limit_bids=data['auction']['limit_bids'])

                elif ('bidders' in data['auction']) and not ('limit_bids' in data['auction']):
                    self.create_auction(addr, self.serial + 1, data['auction']['name'], data['auction']['time-limit'],
                                        data['auction']['description'], data['auction']['type'],
                                        bidders=data['auction']['bidders'])

                elif not ('bidders' in data['auction']) and ('limit_bids' in data['auction']):
                    self.create_auction(addr, self.serial + 1, data['auction']['name'], data['auction']['time-limit'],
                                        data['auction']['description'], data['auction']['type'],
                                        limit_bids=data['auction']['limit_bids'])
                else:
                    self.create_auction(addr, self.serial + 1, data['auction']['name'], data['auction']['time-limit'],
                                        data['auction']['description'], data['auction']['type'])
            elif 'bid' in data:
                self.create_bid(addr, data['bid'])

            elif 'command' in data:
                if 'bid_request' in data['command']:
                    self.send_pow(addr, data['serial'])
                elif 'list_open' in data['command']:
                    self.list_open(addr)
                elif 'list_closed' in data['command']:
                    self.list_closed(addr)
                elif 'check_receipt' in data['command']:
                    self.check_receipt(addr)

    # create an auction according to the client's requested parameters
    def create_auction(self, addr, serial, name, timelimit, description, type, bidders=None, limit_bids=None):
        try:
            blockchain = Blockchain(serial, name, timelimit, description, type, bidders, limit_bids, state='active')
            self.serial = self.serial + 1

            print("\nNew auction created!")
            print(blockchain.info())

            # add new auction to the active auctions list
            self.active_auctions.append(blockchain)

            msg = json.dumps({'ack': 'ok'})
            sent = self.sock.sendto(str.encode(msg), addr)
        except:
            print("Cannot create auction!\n")
            msg = json.dumps({'ack': 'not ok'})
            sent = self.sock.sendto(str.encode(msg), addr)

    # send the size of the hash to be calculated (challenge)
    def send_pow(self, address_client, serial):
        type = ""

        for auction in self.active_auctions:
            if auction.serial == serial:
                print("found the serial")
                type = auction['type']
        msg = json.dumps({'size': '3', 'type': type})
        sent = self.sock.sendto(str.encode(msg), address_client)

    # create a bid to an existent auction
    def create_bid(self, addr, data):
        auction_exists = False

        for auction in self.active_auctions:
            if data['serial'] == str(auction.serial):
                auction_exists = True
                block = Block(data['serial'], data['hash'], data['amount'], data['identity'], data['timestamp'])
                auction.add_block(block)
                print("\nNew bid created for auction {}".format(auction.serial))
                print(block.info())

                msg = json.dumps({'ack': 'ok'})
                sent = self.sock.sendto(str.encode(msg), addr)

        if auction_exists is False:
            msg = json.dumps({'ack': 'not ok'})
            sent = self.sock.sendto(str.encode(msg), addr)
            print("Sent ack {}".format(sent))

    # list active auctions
    def list_open(self, address_client):
        try:
            msg = ""
            for auction in self.active_auctions:
                msg = msg + str(auction) + "\n"

            msg = json.dumps(msg)
            sent = self.sock.sendto(str.encode(msg), address_client)

            print("Sent list of active auctions!")
        except:
            print("Exception: Can't list active auctions")

    # list closed auctions
    def list_closed(self, address_client):

        try:
            msg = ""
            for auction in self.closed_auctions:
                msg = msg + str(auction) + "\n"

            msg = json.dumps(msg)
            sent = self.sock.sendto(str.encode(msg), address_client)

            print("Sent list of closed auctions!")

        except:
            print("Exception: Can't list closed auctions")

    # send information to the client for him/her to check his/her receipt
    def check_receipt(self, address_client):
        print("Checking the validity of the receipt")

    def close(self):
        self.sock.close()


if __name__ == "__main__":
    r = Repository(HOST, PORT_REPO)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
        r.close()
