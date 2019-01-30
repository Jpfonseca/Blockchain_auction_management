import os, datetime, sys, json, base64, re, copy

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

MAX_BUFFER_SIZE = 10000


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
        self.loggedInClient = 0

        self.host = host
        self.port = port
        # public keys
        self.clients_pubkey = set()

        self.man_pubkey = None
        # list of the addresses
        self.address_client = []
        self.manager_address = None
        # list of active and closed auctions (blockchain object
        self.active_auctions = []
        self.closed_auctions = []
        self.all_auctions = []
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # incremental serial number
        self.serial = 0
        # hash of the previous block (auction serial, previous hash)
        self.hash_prev = {}
        # generate public and private key
        self.certgen = GenerateCertificates()
        self.certops = CertificateOperations()
        self.crypto = CryptoUtils()
        # dictionary of 'id' and public key
        self.pubkey_dict = {}
        # auction creator - cert dictionary
        self.auction_certs = {}

    # server and client exchange public keys
    def start(self):
        # verify if repository private key already exists. load if true
        if self.certgen.checkExistence(self.name):
            self.certgen.loadPrivateKeyFromFile(self.privKname, password=self.password)
        else:
            self.certgen.writePrivateKeyToFile(self.privKname, password=self.password)

        # get public key of repository and store to global variable
        self.repo_pubkey = self.certgen.publicKeyToBytes()
        #self.repo_pubkey = base64.b64encode(self.repo_pubkeyb).decode()

        print("Listening...")

        # 1) exchange public keys with the manager
        self.mylogger.log(INFO, "Exchanging public key with the manager")
        data1, self.manager_address = self.sock.recvfrom(MAX_BUFFER_SIZE)
        print("> manager pubkey received")
        msg = json.dumps({'repo_pubk': self.repo_pubkey.decode()})
        bytes = self.sock.sendto(msg.encode(), self.manager_address)
        self.mylogger.log(INFO, "Manager Pubkey received")

        # store the received manager public key in a global variable
        data1 = json.loads(data1)
        if 'man_pubk' in data1:
            self.man_pubkey = data1['man_pubk']
        self.mylogger.log(INFO, "Man Pubkey : \n{}".format(self.man_pubkey))

        # 2) exchange public key with client
        self.mylogger.log(INFO, "Exchanging cert/pubkey with the client")
        data2, client_addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
        print("> client pubkey received")
        bytes = self.sock.sendto(msg.encode(), client_addr)
        self.mylogger.log(INFO, "Client Pubkey received")

        data2 = json.loads(data2)
        self.clientLogin(data2, client_addr)

        self.loop()

    # loop that waits for messages of manager or client
    def loop(self):
        while (True):
            date_time = datetime.datetime.now()
            for auction in self.active_auctions:
                timestamp_auction = datetime.datetime.strptime(auction.timestamp, '%m/%d/%Y, %H:%M:%S')
                delta = date_time - timestamp_auction
                seconds = delta.days * 24 * 3600 + delta.seconds

                time_limit = re.findall('\d+', auction.time_limit)
                time_limit = (int(time_limit[0]) * 3600) + (int(time_limit[1]) * 60) + int(time_limit[2])

                print("> {} seconds have passed on auction {}".format(auction.serial, seconds))

                # alert manager that the auction has ended. It will then calculate the winner
                if seconds > time_limit:
                    print("> auction {} has ended".format(auction.serial))
                    self.closed_auctions.append(auction)
                    self.active_auctions.remove(auction)

                    file = "auction{}.txt".format(auction.serial)
                    current_path = os.getcwd()
                    path = "{}/auctions/{}".format(current_path, file)

                    msg = {'payload': {'end': path}}
                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature
                    bytes = self.sock.sendto(json.dumps(msg).encode(), self.manager_address)

                    data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                    data = json.loads(data)

                    signature = base64.b64decode(data['signature'])
                    if self.validSignature(self.man_pubkey, json.dumps(data['payload']), signature):
                        # the winner was found by the manager. The updated blockchain in the file is loaded onto the program
                        if data['payload']['ack'] == 'ok':
                            with open(path) as f:
                                lines = f.readlines()
                            lines = [x.strip("\n") for x in lines]

                            blockchain = None
                            for i in range(len(lines)):

                                lines_dict = literal_eval(lines[i])

                                if i == 0:
                                    blockchain = Blockchain(lines_dict['key'], lines_dict['cert'], lines_dict['serial'], lines_dict['id'],
                                                            lines_dict['timestamp'], lines_dict['name'], lines_dict['time-limit'],
                                                            lines_dict['description'], lines_dict['type'], lines_dict['bidders'],
                                                            lines_dict['limit_bids'], lines_dict['state'], lines_dict['winner'],
                                                            lines_dict['winner_amount'])

                                else:
                                    block = Block(lines_dict['key'], lines_dict['cert'], lines_dict['serial'],
                                                  lines_dict['hash'], lines_dict['hash_prev'], lines_dict['amount'],
                                                  lines_dict['name'], lines_dict['id'], lines_dict['timestamp'])

                                    blockchain.add_block(block)

                            for a in range(len(self.closed_auctions)):
                                if auction.serial == blockchain.serial:
                                    self.closed_auctions[a] = blockchain

                            for a in range(len(self.all_auctions)):
                                if auction.serial == blockchain.serial:
                                    self.all_auctions[a] = blockchain

                    else:
                        print("> couldn't find the winner")

            data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.manager_address):
                print("> client pubkey received")
                msg = json.dumps({'repo_pubk': self.repo_pubkey.decode()})
                bytes = self.sock.sendto(msg.encode(), addr)
                self.clientLogin(data, addr)
                self.loggedInClient += 1
            else:
                if 'auction' in data['payload']:
                    signature = base64.b64decode(data['signature'])
                    if data['payload']['valid']:
                        if self.validSignature(self.man_pubkey, json.dumps(data['payload']), signature):
                            data2 = data['payload']
                            if ('bidders' in data2['auction']) and ('limit_bids' in data2['auction']):
                                self.create_auction(addr, data2['auction']['key'], data2['auction']['cert'],
                                                    self.serial + 1, data2['auction']['id'], data2['auction']['timestamp'],
                                                    data2['auction']['name'], data2['auction']['time-limit'],
                                                    data2['auction']['description'], data2['auction']['type'],
                                                    bidders=data2['auction']['bidders'], limit_bids=data2['auction']['limit_bids'])

                            elif ('bidders' in data2['auction']) and not ('limit_bids' in data2['auction']):
                                self.create_auction(addr, data2['auction']['key'], data2['auction']['cert'],
                                                    self.serial + 1, data2['auction']['id'], data2['auction']['timestamp'],
                                                    data2['auction']['name'], data2['auction']['time-limit'],
                                                    data2['auction']['description'], data2['auction']['type'],
                                                    bidders=data2['auction']['bidders'])

                            elif not ('bidders' in data2['auction']) and ('limit_bids' in data2['auction']):
                                self.create_auction(addr, data2['auction']['key'], data2['auction']['cert'],
                                                    self.serial + 1, data2['auction']['id'], data2['auction']['timestamp'],
                                                    data2['auction']['name'], data2['auction']['time-limit'],
                                                    data2['auction']['description'], data2['auction']['type'],
                                                    limit_bids=data2['auction']['limit_bids'])
                            else:
                                self.create_auction(addr, data2['auction']['key'], data2['auction']['cert'],
                                                    self.serial + 1, data2['auction']['id'], data2['auction']['timestamp'],
                                                    data2['auction']['name'], data2['auction']['time-limit'],
                                                    data2['auction']['description'], data2['auction']['type'])

                elif 'bid' in data['payload']:
                    data2 = copy.deepcopy(data)
                    signature = base64.b64decode(data2['payload'].pop('sig_c'))
                    if self.crypto.verifySignatureCC(self.pubkey_dict[data['payload']['bid']['id']], json.dumps(data2['payload']), signature):
                        self.place_bid(addr, data['payload'])

                elif 'command' in data['payload']:
                    signature = base64.b64decode(data['signature'])
                    data2 = data['payload']
                    payload = json.dumps(data2)
                    if 'bid_request' in data2['command']:
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                            self.send_pow(addr, data2)
                    elif 'list_open' in data2['command']:
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                            self.list_open(addr)
                    elif 'list_closed' in data2['command']:
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                            self.list_closed(addr)
                    elif 'bid_auction' in data2['command']:
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                            self.bids_auction(addr, data2['serial'])
                    elif 'bid_client' in data2['command']:
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                            self.bids_client(addr, data2['c_id'])
                    elif 'check_receipt' in data2['command']:
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                            self.check_receipt(addr)

                if 'exit' in data['payload']:
                    msg = json.dumps({'payload': {'exit': 'client exit'}})
                    signature = base64.b64decode(data['signature'])

                    if self.crypto.verifySignatureCC(self.pubkey_dict[data['payload']['id']], json.dumps(data['payload']), signature):
                        self.loggedInClient -= 1
                        if self.loggedInClient <= 0:
                            self.mylogger.log(INFO, "Exiting Repository")
                            sys.exit(0)

                for auction in self.active_auctions:
                    file = "auction{}.txt".format(auction.serial)
                    auction.save_to_file(file)

    # create an auction according to the client's requested parameters
    def create_auction(self, addr, key, cert, serial, id, timestamp, name, timelimit, description, type, bidders=None,
                       limit_bids=None):
        try:
            blockchain = Blockchain(key, cert, serial, id, timestamp, name, timelimit, description, type, bidders, limit_bids,
                                    state='active')
            self.serial = self.serial + 1

            print("> auction creation: OK")
            self.active_auctions.append(blockchain)
            self.all_auctions.append(blockchain)

            self.hash_prev[str(serial)] = '0'

            msg = {'payload': {'ack': 'ok', 'info': 'auction', 'id': id, 'serial': str(serial)}}
            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), addr)

        except:
            print("> auction creation: NOT OK\n")
            msg = {'payload': {'ack': 'nok', 'info': 'auction', 'id': id}}
            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), addr)

    # send the size of the hash to be calculated (proof-of-work)
    def send_pow(self, address_client, data):
        try:
            type = ""
            auction_exists = False
            # validate bid with API
            for auction in self.active_auctions:
                if str(auction.serial) == data['serial']:
                    type = auction.type
                    auction_exists = True

            if auction_exists is False:
                msg = {'payload': {'ack': 'nok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
            else:
                msg = {'payload': {'size': '7', 'type': type, 'hash_prev': self.hash_prev[data['serial']]}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
        except:
            print("Cannot send proof-of-work size")
            raise

    # create a bid in an existent auction
    def place_bid(self, addr, data):
        try:
            client_address = addr
            for auction in self.active_auctions:
                if data['bid']['serial'] == str(auction.serial):
                    block = Block(data['bid']['key'], data['bid']['cert'], data['bid']['serial'], data['bid']['hash'],
                                  data['bid']['hash_prev'], data['bid']['amount'], data['bid']['name'],
                                  data['bid']['id'], data['bid']['timestamp'])

                    self.hash_prev[data['bid']['serial']] = data['bid']['hash']

                    # send block to manager for validation
                    msg = {'payload': {'bid_valid': data}}
                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature

                    bytes = self.sock.sendto(json.dumps(msg).encode(), self.manager_address)

                    # if manager signature is valid and bid is valid
                    data2, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                    data2 = json.loads(data2)

                    signature = base64.b64decode(data2['signature'])
                    payload = json.dumps(data2['payload'])

                    if self.validSignature(self.man_pubkey, payload, signature):
                        # if bid is valid according to the manager, the bid is stored
                        if data2['payload']['valid'] is True:
                            auction.add_block(block)
                            print("> bid creation in auction {}: OK".format(auction.serial))

                            # sign receipt
                            signature = base64.b64encode(self.certgen.signData(json.dumps(data2['payload']['receipt']))).decode()
                            data2['payload']['receipt']['sig_r'] = signature

                            msg = {'payload': {'ack': 'ok', 'receipt': data2['payload']['receipt']}}

                            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                            msg['signature'] = signature

                            bytes = self.sock.sendto(json.dumps(msg).encode(), client_address)
                        else:
                            print("> bid creation in auction {}: NOK".format(auction.serial))
                            msg = {'payload': {'ack': 'nok', 'info': 'bid'}}

                            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                            msg['signature'] = signature
                            bytes = self.sock.sendto(json.dumps(msg).encode(), client_address)

        except:
            print("Cannot create bid")
            raise

    # list active auctions
    def list_open(self, address_client):
        try:
            auctions = ""
            for auction in self.active_auctions:
                auctions = auctions + str(auction.info_user()) + "\n"

            if auctions != "":
                msg = {'payload': auctions}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
                print("> sending list of active auctions")
            else:
                msg = {'payload': {'ack': 'nok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
        except:
            print("Can't send active auctions")
            raise

    # list closed auctions
    def list_closed(self, address_client):
        try:
            auctions = ""
            for auction in self.closed_auctions:
                auctions = auctions + str(auction.info_user()) + "\n"

            if auctions != "":
                msg = {'payload': auctions}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
                print("> sending list of closed auctions")
            else:
                msg = {'payload': {'ack': 'nok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

        except:
            print("Can't send active auctions")
            raise

    # display all bids of an auction
    def bids_auction(self, address_client, serial):
        try:
            msg = {}
            i = 0
            result = None
            auctions_exists = False

            for auction in self.all_auctions:
                if auction.serial == int(serial):
                    auctions_exists = True
                    result = auction.bids_auction(serial)

            if auctions_exists:
                for bid in result:
                    bid_number = "bid_{}".format(i)
                    msg[bid_number] = bid
                    i = i + 1

                msg = {'payload': msg}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
                print("\n> sent list of bids of auction {}".format(serial))
            else:
                msg = {'payload': {'ack': 'nok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

        except:
            print("> cannot send list of bids of auction {}".format(serial))

    # display all bids sent by a client
    def bids_client(self, address_client, id):
        try:

            msg = {}
            i = 0
            result = None
            client_exists = False

            for auction in self.all_auctions:
                if str(auction.id) == id:
                    client_exists = True
                    result = auction.bids_client(id)

            if client_exists:
                for bid in result:
                    bid_number = "bid_{}".format(i)
                    msg[bid_number] = bid
                    i = i + 1

                msg = {'payload': msg}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
                print("\n> sent list of bids of client {}".format(id))
            else:
                msg = {'payload': {'ack': 'nok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

        except:
            print("> can't send list of bids of client {}".format(id))

    # send bid info to the client for him/her to check against the receipt
    def check_receipt(self, address_client):
        print("> checking the validity of the receipt")

    def validSignature(self, pubk, message, signature):
        try:
            pubk = self.crypto.loadPubk(pubk)
            if not self.crypto.verifySignatureServers(pubk, message, signature):
                return False
            return True
        except:
            print("Cannot validate signature")
            raise

        # store client pubk

    def clientLogin(self, message, client_addr):
        try:
            cert = None
            if 'c_pubk' in message:
                self.mylogger.log(INFO, "Client Pubkey : \n{}".format(message['c_pubk']))
                self.loggedInClient += 1
                self.pubkey_dict[message['id']] = message['c_pubk']
                self.address_client.append(client_addr)
        except:
            print("Cannot sign up new client")
            raise

    def close(self):
        self.sock.close()


if __name__ == "__main__":
    r = Repository(HOST, PORT_REPO)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
