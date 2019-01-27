import os,datetime,sys,json,base64,re

from os import listdir
from ast import literal_eval
from socket import *
from blockchain import *

from logging import DEBUG, ERROR, INFO

from log import LoggyLogglyMcface
from security import *
from cc_interface import PortugueseCitizenCard

HOST = "127.0.0.1"
PORT_MAN = 8080
PORT_REPO = 8081

MAX_BUFFER_SIZE = 8192

class Repository():

    def __init__(self, host, port):
        LOG = "./log.txt"

        for filename in listdir("./"):
            if filename == "log.txt":
                os.remove(LOG)

        self.mylogger = LoggyLogglyMcface(name=Repository.__name__)
        self.mylogger.log(INFO, "Entering Repository interface")

        self.name = Repository.__name__
        self.privKname = "privK" + self.name
        self.password = "123"

        self.repo_pubkey = None
        self.repo_pubkeyb = None
        self.loggedInClient=0

        self.host = host
        self.port = port
        # public keys
        self.clients_pubkey = set()

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
        # generate public and private key
        self.certgen = GenerateCertificates()
        self.certops = CertificateOperations()
        self.crypto = CryptoUtils()
        # dictionary of 'id' and public key
        self.pubkey_dict = {}

    # server and client exchange public keys
    def start(self):
        # verify if repository private key already exists. load if true
        if self.certgen.checkExistence(self.name):
            self.certgen.loadPrivateKeyFromFile(self.privKname, password=self.password)
        else:
            self.certgen.writePrivateKeyToFile(self.privKname, password=self.password)

        # get public key of repository and store to global variable
        self.repo_pubkeyb = self.certgen.publicKeyToBytes()
        self.repo_pubkey = base64.b64encode(self.repo_pubkeyb).decode()

        print("Listening...")

        # 1) exchange public keys with the manager
        self.mylogger.log(INFO, "Exchanging public key with the manager")
        data1, self.manager_address = self.sock.recvfrom(MAX_BUFFER_SIZE)
        print("> manager pubkey received")
        msg = json.dumps({'repo_pubk': self.repo_pubkey})
        bytes = self.sock.sendto(str.encode(msg), self.manager_address)
        self.mylogger.log(INFO, "Manager Pubkey received")

        # store the received manager public key in a global variable
        data1 = json.loads(data1)
        if 'man_pubk' in data1:
            self.man_pubkey = base64.b64decode(data1['man_pubk'].encode())
        self.mylogger.log(INFO, "Man Pubkey : \n{}".format(self.man_pubkey))

        # 2) exchange public key with client
        self.mylogger.log(INFO, "Exchanging cert/pubkey with the client")
        data2, client_addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
        print("> client pubkey received")
        bytes = self.sock.sendto(str.encode(msg), client_addr)
        self.mylogger.log(INFO, "Client Pubkey received")

        data2 = json.loads(data2)
        self.clientLogin(data2,client_addr)

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
                    bytes = self.sock.sendto(str.encode(msg), self.manager_address)
                    data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
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
                                blockchain = Blockchain(dict['serial'], dict['id'], dict['timestamp'], dict['name'],
                                                        dict['time-limit'],
                                                        dict['description'], dict['type'], dict['bidders'],
                                                        dict['limit_bids'], dict['state'], dict['winner'], dict['winner_amount'])
                            else:
                                block = Block(dict['serial'], dict['hash'], dict['hash_prev'], dict['amount'], dict['name'],
                                              dict['id'], dict['timestamp'])
                                blockchain.add_block(block)

                        for a in range(len(self.closed_auctions)):
                            if auction.serial == blockchain.serial:
                                self.closed_auctions[a] = blockchain

            data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.manager_address):
                print("> client pubkey received")
                msg = json.dumps({'repo_pubk': self.repo_pubkey})
                bytes = self.sock.sendto(str.encode(msg), addr)
                self.clientLogin(data, addr)
                self.loggedInClient += 1

            if 'auction' in data['payload']:
                if data['payload']['valid']:
                    signature = base64.b64decode(data['signature'])
                    auction = json.dumps(data['payload'])

                    if self.validSignature(self.man_pubkey, auction, signature):
                        data = data['payload']
                        if ('bidders' in data['auction']) and ('limit_bids' in data['auction']):
                            self.create_auction(addr, self.serial + 1, data['auction']['id'],
                                                data['auction']['timestamp'],
                                                data['auction']['name'],
                                                data['auction']['time-limit'], data['auction']['description'],
                                                data['auction']['type'], bidders=data['auction']['bidders'],
                                                limit_bids=data['auction']['limit_bids'])

                        elif ('bidders' in data['auction']) and not ('limit_bids' in data['auction']):
                            self.create_auction(addr, self.serial + 1, data['auction']['id'],
                                                data['auction']['timestamp'],
                                                data['auction']['name'],
                                                data['auction']['time-limit'], data['auction']['description'],
                                                data['auction']['type'], bidders=data['auction']['bidders'])

                        elif not ('bidders' in data['auction']) and ('limit_bids' in data['auction']):
                            self.create_auction(addr, self.serial + 1, data['auction']['id'],
                                                data['auction']['timestamp'],
                                                data['auction']['name'],
                                                data['auction']['time-limit'], data['auction']['description'],
                                                data['auction']['type'], limit_bids=data['auction']['limit_bids'])
                        else:
                            self.create_auction(addr, self.serial + 1, data['auction']['id'],
                                                data['auction']['timestamp'],
                                                data['auction']['name'],
                                                data['auction']['time-limit'], data['auction']['description'],
                                                data['auction']['type'])

            elif 'bid' in data:
                self.create_bid(addr, data['bid'])

            elif 'command' in data:
                signature = base64.b64decode(data['signature'])
                payload = json.dumps(data['payload'])

                data = data['payload']
                if 'bid_request' in data['command']:
                    if self.validSignature(self.man_pubkey, payload, signature):
                        self.send_pow(addr, data['serial'])
                elif 'list_open' in data['command']:
                    if self.validSignature(self.pubkey_dict[data['id']], payload, signature):
                        self.list_open(addr)
                elif 'list_closed' in data['command']:
                    if self.validSignature(self.pubkey_dict[data['id']], payload, signature):
                        self.list_closed(addr)
                elif 'bid_auction' in data['command']:
                    if self.validSignature(self.man_pubkey, payload, signature):
                        self.bids_auction(addr, data['serial'])
                elif 'check_receipt' in data['command']:
                    if self.validSignature(self.man_pubkey, payload, signature):
                        self.check_receipt(addr)
                elif 'bid_client' in data['command']:
                    if self.validSignature(self.man_pubkey, payload, signature):
                        self.bids_client(addr, data['id'])

            if 'exit' in data:
                self.loggedInClient -= 1
                if self.loggedInClient == 0:
                    self.mylogger.log(INFO, "Exiting Repository")
                    sys.exit(-1)

            for auction in self.active_auctions:
                file = "auction{}.txt".format(auction.serial)
                auction.save_to_file(file)

    # create an auction according to the client's requested parameters
    def create_auction(self, addr, serial, id, timestamp, name, timelimit, description, type, bidders=None,
                       limit_bids=None):
        try:
            blockchain = Blockchain(serial, id, timestamp, name, timelimit, description, type, bidders, limit_bids,
                                    state='active')
            self.serial = self.serial + 1

            print("> auction creation: OK")
            self.active_auctions.append(blockchain)
            self.all_auctions.append(blockchain)

            print("criei a auction no repo, prova:")
            print(self.active_auctions)
            
            msg = {'payload': {'ack': 'ok', 'info':'auction', 'id': id}}
            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(str.encode(json.dumps(msg)), addr)
        except:
            print("> auction creation: NOT OK\n")
            msg = {'payload': {'ack': 'nok', 'info': 'auction', 'id': id}}
            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(str.encode(json.dumps(msg)), addr)

    # send the size of the hash to be calculated (proof-of-work)
    def send_pow(self, address_client, serial):
        type = ""

        for auction in self.active_auctions:
            if auction.serial == serial:
                type = auction['type']
        msg = json.dumps({'size': '10', 'type': type, 'signature': 'oi'})
        bytes = self.sock.sendto(str.encode(msg), address_client)

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
                bytes = self.sock.sendto(msg.encode(), addr)

        if auction_exists is False:
            msg = json.dumps({'ack': 'not ok'})
            bytes = self.sock.sendto(msg.encode(), addr)

    # list active auctions
    def list_open(self, address_client):
        try:
            msg = ""
            for auction in self.active_auctions:
                msg = msg + str(auction.info()) + "\n"

            signature = base64.b64encode(self.certgen.signData(json.dumps(msg))).decode()
            msg = {'payload': msg, 'signature': signature}
            bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
            print("> sending list of active auctions")
        except:
            print("Exception: Can't list active auctions")

    # list closed auctions
    def list_closed(self, address_client):
        try:
            msg = ""
            for auction in self.closed_auctions:
                msg = msg + str(auction.info()) + "\n"

            signature = base64.b64encode(self.certgen.signData(json.dumps(msg))).decode()
            msg = {'payload': msg, 'signature': signature}
            bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
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

            bytes = self.sock.sendto(str.encode(msg), address_client)
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

            bytes = self.sock.sendto(str.encode(msg), address_client)
            print("\n> sent list of bids of client {}".format(id))

        except:
            print("> can't send list of bids of client {}".format(id))

    # send bid info to the client for him/her to check against the receipt
    def check_receipt(self, address_client):
        print("> checking the validity of the receipt")

    def validSignature(self, pubk, message, signature):
        pubk = self.crypto.loadPubk(pubk)
        if not self.crypto.verifySignatureServers(pubk, message, signature):
            return False
        return True

        # store client pubk

    def clientLogin(self, message, client_addr):
        cert = None
        if 'c_pubk' in message:
            pubk = base64.b64decode(message['c_pubk'].encode())

        self.mylogger.log(INFO, "Client Pubkey : \n{}".format(pubk))

        self.loggedInClient += 1
        self.pubkey_dict[message['id']] = pubk
        self.address_client.append(client_addr)

    def close(self):
        self.sock.close()


if __name__ == "__main__":
    r = Repository(HOST, PORT_REPO)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
