import datetime
import json
import os
from ast import literal_eval
from socket import *
from blockchain import *
import re

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
        self.repo_pubkey = '123'
        self.man_pubkey = None
        # list of the addresses
        self.address_client = []
        self.manager_address = None
        # list of active and closed auctions
        self.active_auctions = []
        self.closed_auctions = []
        self.all_auctions = []
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # incremental serial number
        self.serial = 0
        # hash of the previous block (auction serial, previous hash)
        self.hash_prev = {'1': '0'}

    # server and client exchange public keys
    def start(self):

        print("Listening...")

        self.mylogger.log(INFO, "Exchanging public key with the manager")
        data1, self.manager_address = self.sock.recvfrom(4096)
        print("> manager pubkey received")
        msg = json.dumps({'repo_pubk': self.repo_pubkey})
        sent = self.sock.sendto(str.encode(msg), self.manager_address)
        self.mylogger.log(INFO, "Manager Pubkey received")

        self.mylogger.log(INFO, "Exchanging public key with the client")
        data2, client_addr = self.sock.recvfrom(4096)
        print("> client pubkey received")
        sent = self.sock.sendto(str.encode(msg), client_addr)
        self.address_client.append(client_addr)
        self.mylogger.log(INFO, "Client Pubkey received")

        # save public keys
        data1 = json.loads(data1)
        if 'man_pubk' in data1:
            self.man_pubkey = data1['man_pubk']
        data2 = json.loads(data2)
        if 'c_pubk' in data2:
            self.clients_pubkey.add(data2['c_pubk'])

        self.mylogger.log(INFO, "Repo Pubkey : \n{}\nClient Pubkey : \n{}".format(data1['man_pubk'],data2['c_pubk']))

        self.loop()

    # loop that waits for messages of manager or client
    def loop(self):
        while (True):

            date_time = datetime.datetime.now()
            for auction in self.active_auctions:
                timestamp_auction = datetime.datetime.strptime(auction.timestamp, '%m/%d/%Y, %H:%M:%S')
                delta = date_time - timestamp_auction
                seconds = delta.days*24 * 3600 + delta.seconds

                time_limit = re.findall('\d+', auction.time_limit)
                time_limit = (int(time_limit[0])*3600) + (int(time_limit[1])*60) + int(time_limit[2])

                # alert manager that the auction has ended. It will then calculate the winner
                if seconds > time_limit:
                    print("> auction {} has ended".format(auction.serial))
                    self.closed_auctions.append(auction)
                    self.active_auctions.remove(auction)

                    current_path = os.getcwd()
                    path = "{}/auctions/{}".format(current_path, file)

                    msg = json.dumps({'end': path, 'signature': 'oi'})
                    sent = self.sock.sendto(str.encode(msg), self.manager_address)
                    data, addr = self.sock.recvfrom(4096)
                    data = json.loads(data)

                    # the winner was found by the manager. The updated blockchain in the file is loaded onto the program
                    if data['ack'] == 'ok':
                        with open(path) as f:
                            lines = f.readlines()
                        lines = [x.strip("\n") for x in lines]

                        blockchain = None
                        for i in range(len(lines)):
                            dict = literal_eval(lines[i])
                            if i == 0:
                                blockchain = Blockchain(dict['serial'], dict['timestamp'], dict['name'], dict['time-limit'],
                                                        dict['description'], dict['type'], dict['bidders'],
                                                        dict['limit_bids'], dict['state'], dict['winner'], dict['winner_amount'])
                            else:
                                block = Block(dict['serial'], dict['hash'], dict['hash_prev'], dict['amount'], dict['name'],
                                              dict['id'], dict['timestamp'])
                                blockchain.add_block(block)

                        for a in range(len(self.closed_auctions)):
                            if auction.serial == blockchain.serial:
                                self.closed_auctions[a] = blockchain

            data, addr = self.sock.recvfrom(4096)
            data = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.manager_address):
                print("> client pubkey received")
                msg = json.dumps({'repo_pubk': self.repo_pubkey, 'signature': 'oi'})
                sent = self.sock.sendto(str.encode(msg), addr)
                self.address_client.append(addr)
                self.clients_pubkey.add(data['c_pubk'])

            if 'auction' in data:
                if ('bidders' in data['auction']) and ('limit_bids' in data['auction']):
                    self.create_auction(addr, self.serial + 1, data['auction']['timestamp'], data['auction']['name'],
                                        data['auction']['time-limit'], data['auction']['description'],
                                        data['auction']['type'], bidders=data['auction']['bidders'],
                                        limit_bids=data['auction']['limit_bids'])

                elif ('bidders' in data['auction']) and not ('limit_bids' in data['auction']):
                    self.create_auction(addr, self.serial + 1, data['auction']['timestamp'], data['auction']['name'],
                                        data['auction']['time-limit'], data['auction']['description'],
                                        data['auction']['type'], bidders=data['auction']['bidders'])

                elif not ('bidders' in data['auction']) and ('limit_bids' in data['auction']):
                    self.create_auction(addr, self.serial + 1, data['auction']['timestamp'], data['auction']['name'],
                                        data['auction']['time-limit'],data['auction']['description'],
                                        data['auction']['type'], limit_bids=data['auction']['limit_bids'])
                else:
                    self.create_auction(addr, self.serial + 1, data['auction']['timestamp'], data['auction']['name'],
                                        data['auction']['time-limit'], data['auction']['description'],
                                        data['auction']['type'])

            elif 'bid' in data:
                self.create_bid(addr, data['bid'])

            elif 'command' in data:
                if 'bid_request' in data['command']:
                    self.send_pow(addr, data['serial'])
                elif 'list_open' in data['command']:
                    self.list_open(addr)
                elif 'list_closed' in data['command']:
                    self.list_closed(addr)
                elif 'bid_auction' in data['command']:
                    self.bids_auction(addr, data['serial'])
                elif 'check_receipt' in data['command']:
                    self.check_receipt(addr)
                elif 'bid_client' in data['command']:
                    self.bids_client(addr, data['id'])
                elif 'outcome' in data['command']:
                    self.outcome_auction(addr, data['serial'])

            for auction in self.active_auctions:
                file = "auction{}.txt".format(auction.serial)
                auction.save_to_file(file)

    # create an auction according to the client's requested parameters
    def create_auction(self, addr, serial, timestamp, name, timelimit, description, type, bidders=None, limit_bids=None):
        try:
            blockchain = Blockchain(serial, timestamp, name, timelimit, description, type, bidders, limit_bids, state='active')
            self.serial = self.serial + 1

            print("> auction creation: OK")
            self.active_auctions.append(blockchain)
            self.all_auctions.append(blockchain)

            msg = json.dumps({'ack': 'ok', 'info': blockchain.info(), 'signature': 'oi'})
            sent = self.sock.sendto(str.encode(msg), addr)
        except:
            print("> auction creation: NOT OK\n")
            msg = json.dumps({'ack': 'not ok', 'signature': 'oi'})
            sent = self.sock.sendto(str.encode(msg), addr)

    # send the size of the hash to be calculated (proof-of-work
    def send_pow(self, address_client, serial):
        type = ""

        for auction in self.active_auctions:
            if auction.serial == serial:
                type = auction['type']
        msg = json.dumps({'size': '10', 'type': type, 'signature': 'oi'})
        sent = self.sock.sendto(str.encode(msg), address_client)

    # create a bid in an existent auction
    def create_bid(self, addr, data):
        auction_exists = False

        for auction in self.active_auctions:
            if data['serial'] == str(auction.serial):
                auction_exists = True

                if self.hash_prev['1'] != '0':
                    block = Block(data['serial'], data['hash'], self.hash_prev[str(auction.serial)], data['amount'],
                              data['name'], data['identity'], data['timestamp'])
                else:
                    block = Block(data['serial'], data['hash'], '0', data['amount'],
                                  data['name'], data['identity'], data['timestamp'])

                auction.add_block(block)
                print("> bid creation in auction {}: OK".format(auction.serial))

                self.hash_prev[str(auction.serial)] = data['hash']

                msg = json.dumps({'ack': 'ok', 'info': block.info(), 'signature': 'oi'})
                sent = self.sock.sendto(str.encode(msg), addr)

        if auction_exists is False:
            msg = json.dumps({'ack': 'not ok'})
            sent = self.sock.sendto(str.encode(msg), addr)

    # list active auctions
    def list_open(self, address_client):
        try:
            msg = ""
            for auction in self.active_auctions:
                msg = msg + str(auction.info()) + "\n"

            msg = json.dumps(msg)
            sent = self.sock.sendto(str.encode(msg), address_client)

            print("> sending list of active auctions")
        except:
            print("Exception: Can't list active auctions")

    # list closed auctions
    def list_closed(self, address_client):
        try:
            msg = ""
            for auction in self.closed_auctions:
                msg = msg + str(auction.info()) + "\n"

            msg = json.dumps(msg)
            sent = self.sock.sendto(str.encode(msg), address_client)

            print("> sending list of closed auctions")

        except:
            print("Exception: Can't list closed auctions")

    # display all bids of an auction
    def bids_auction(self, address_client, serial):
        try:
            msg = {}
            i = 0
            result = None

            for auction in self.all_auctions:
                if auction.serial == int(serial):
                    result = auction.bids_auction(serial)

            for bid in result:
                bid_number = "bid_{}".format(i)
                msg[bid_number] = bid
                i = i+1
            msg['signature'] = 'oi'
            msg = json.dumps(msg)

            sent = self.sock.sendto(str.encode(msg), address_client)
            print("\n> sent list of bids of auction {}". format(serial))
        except:
            print("> can't send list of bids of auction {}".format(serial))

    # display all bids sent by a client
    def bids_client(self, address_client, id):
        try:
            msg = {}
            i = 0
            result = None

            for auction in self.all_auctions:
                result = auction.bids_client(id)
                print(result)
                for bid in result:
                    bid_number = "bid_{}".format(i)
                    msg[bid_number] = bid
                    i = i+1

            msg['signature'] = 'oi'
            msg = json.dumps(msg)

            sent = self.sock.sendto(str.encode(msg), address_client)
            print("\n> sent list of bids of client {}".format(id))

        except:
            print("> can't send list of bids of client {}".format(id))

    # send bid info to the client for him/her to check against the receipt
    def check_receipt(self, address_client):
        print("> checking the validity of the receipt")

    def close(self):
        self.sock.close()


if __name__ == "__main__":
    r = Repository(HOST, PORT_REPO)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
