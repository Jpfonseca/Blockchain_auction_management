import hashlib
import os, datetime, sys, json, base64, re, copy
import random
import string

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

        # repository information
        self.name = Repository.__name__
        self.privKname = "privK" + self.name
        self.password = "123"
        self.repo_pubkey = None
        self.man_pubkey = None

        self.host = host
        self.port = port
        self.loggedInClient = 0

        # client public keys
        self.clients_pubkey = set()

        # Addresses of clients and manager
        self.address_client = []
        self.manager_address = None

        # list of active and closed auctions
        self.active_auctions = []
        self.closed_auctions = []
        self.all_auctions = []

        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

        # incremental serial number of the auctions
        self.serial = 0

        # hash of the previous block (auction serial, previous hash)
        self.hash_prev = {}

        # generate public and private key
        self.certgen = GenerateCertificates()
        self.certops = CertificateOperations()
        self.crypto = CryptoUtils()

        # dictionary of id of the client and public key
        self.pubkey_dict = {}
        # client is waiting for message (after sending proof-of-work result)
        self.current_client = None
        self.client_waiting = False

    def start(self):
        """
        Servers and Client exchange public keys
        """
        try:
            # verify if repository private key already exists. load if true
            if self.certgen.checkExistence(self.name):
                self.certgen.loadPrivateKeyFromFile(self.privKname, password=self.password)
            else:
                self.certgen.writePrivateKeyToFile(self.privKname, password=self.password)

            self.repo_pubkey = self.certgen.publicKeyToBytes()

            print("Listening...")

            self.mylogger.log(INFO, "Exchanging public key with the manager")
            data1, self.manager_address = self.sock.recvfrom(MAX_BUFFER_SIZE)
            print("> manager pubkey received")
            msg = json.dumps({'repo_pubk': self.repo_pubkey.decode()})
            bytes = self.sock.sendto(msg.encode(), self.manager_address)
            self.mylogger.log(INFO, "Manager public key received")

            data1 = json.loads(data1)
            if 'man_pubk' in data1:
                self.man_pubkey = data1['man_pubk']
            self.mylogger.log(INFO, "Man Pubkey : \n{}".format(self.man_pubkey))

            self.mylogger.log(INFO, "Exchanging public key with the client")
            data2, client_addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
            print("> client pubkey received")
            bytes = self.sock.sendto(msg.encode(), client_addr)
            self.mylogger.log(INFO, "Client public key received")

            data2 = json.loads(data2)
            self.client_login(data2, client_addr)

            self.loop()
        except:
            self.mylogger.log(INFO, "Cannot start repository")
            raise

    def loop(self):
        """
        The main loop of the repository. It waits for messages of clients
        (both system clients or servers) and calls functions according
        to the received messages
        """
        try:
            while (True):
                date_time = datetime.datetime.now()
                for auction in self.active_auctions:
                    timestamp_auction = datetime.datetime.strptime(auction.timestamp, '%m/%d/%Y, %H:%M:%S')
                    delta = date_time - timestamp_auction
                    seconds = delta.days * 24 * 3600 + delta.seconds

                    time_limit = re.findall('\d+', auction.time_limit)
                    time_limit = (int(time_limit[0]) * 3600) + (int(time_limit[1]) * 60) + int(time_limit[2])

                    print("info: {} seconds have passed on auction {}".format(seconds, auction.serial))

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
                        if self.valid_signature(self.man_pubkey, json.dumps(data['payload']), signature):
                            if data['payload']['ack'] == 'ok':
                                with open(path) as f:
                                    lines = f.readlines()
                                lines = [x.strip("\n") for x in lines]

                                blockchain = None
                                for i in range(len(lines)):

                                    lines_dict = literal_eval(lines[i])

                                    if i == 0:
                                        current_serial = lines_dict['serial']
                                        blockchain = Blockchain(lines_dict['key'], lines_dict['cert'], lines_dict['serial'],
                                                                lines_dict['id'], lines_dict['timestamp'],
                                                                lines_dict['name'], lines_dict['time-limit'],
                                                                lines_dict['description'], lines_dict['type'],
                                                                lines_dict['state'], lines_dict['winner'],
                                                                lines_dict['winner_amount'])

                                    else:
                                        block = Block(lines_dict['key'], lines_dict['cert'], lines_dict['serial'],
                                                      lines_dict['hash'], lines_dict['hash_prev'], lines_dict['amount'],
                                                      lines_dict['name'], lines_dict['id'], lines_dict['timestamp'])

                                        blockchain.add_block(block)

                                for a in range(len(self.closed_auctions)):
                                    if auction.serial == self.closed_auctions[a].serial:
                                        self.closed_auctions[a] = blockchain

                                for a in range(len(self.all_auctions)):
                                    if auction.serial == self.all_auctions[a].serial:
                                        self.all_auctions[a] = blockchain

                                if self.client_waiting:
                                    msg = {'payload': {'ack': 'nok', 'info': 'busy: bid no created'}}
                                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                                    msg['signature'] = signature
                                    bytes = self.sock.sendto(json.dumps(msg).encode(), self.current_client)

                            else:
                                print("> no bids on ended auction {} -> no possible winner".format(auction.serial))
                        else:
                            print("> couldn't find the winner")

                data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                data = json.loads(data)

                if (addr not in self.address_client) and (addr != self.manager_address):
                    print("> client pubkey received")
                    msg = json.dumps({'repo_pubk': self.repo_pubkey.decode()})
                    bytes = self.sock.sendto(msg.encode(), addr)
                    self.client_login(data, addr)

                else:
                    self.client_waiting = False
                    if 'auction' in data['payload']:
                        signature = base64.b64decode(data['signature'])
                        if data['payload']['valid']:
                            if self.valid_signature(self.man_pubkey, json.dumps(data['payload']), signature):
                                data2 = data['payload']

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
                                self.check_receipt(addr, data2['serial'], data2['hash'])
                        elif 'list_ids' in data2['command']:
                            if self.crypto.verifySignatureCC(self.pubkey_dict[data2['id']], payload, signature):
                                self.list_ids(addr)

                    if 'exit' in data['payload']:
                        msg = json.dumps({'payload': {'exit': 'client exit'}})
                        signature = base64.b64decode(data['signature'])

                        if self.crypto.verifySignatureCC(self.pubkey_dict[data['payload']['id']], json.dumps(data['payload']), signature):
                            self.loggedInClient -= 1
                            if self.loggedInClient <= 0:
                                self.mylogger.log(INFO, "Exiting Repository")
                                self.exit(0)

                    for auction in self.active_auctions:
                        file = "auction{}.txt".format(auction.serial)
                        auction.save_to_file(file)
        except:
            self.mylogger.log(INFO, "Exception on repository server's loop ")
            raise

    def create_auction(self, addr, key, cert, serial, id, timestamp, name, timelimit, description, type):
        """
        Create an auction (new blockchain) and store it in a file
        after receiving its parameters from the manager server
        """
        try:
            self.mylogger.log(INFO, "Create auction ")
            blockchain = Blockchain(key, cert, serial, id, timestamp, name, timelimit, description, type, state='active')
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
            self.mylogger.log(INFO, "Auction cannot be created ")
            print("> auction creation: NOT OK\n")
            msg = {'payload': {'ack': 'nok', 'info': 'auction', 'id': id}}
            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), addr)

    # send the proof-of-work to client. The cryptopuzzle is a hash-cash
    def send_pow(self, address_client, data):
        """
        Send proof-of-work to the client (random string and number of zeros required).
        A response with a string and a digest is received and the function calculates
        the SHA256 digest of the string and compares it with the digest, also sent by the client.
        If equal, the client may send the bid parameters.
        """
        try:
            self.mylogger.log(INFO, "Sending proof-of-work to client ")

            type = ""
            auction_exists = False

            for auction in self.active_auctions:
                if str(auction.serial) == data['serial']:
                    type = auction.type
                    auction_exists = True

            if auction_exists is False:
                msg = {'payload': {'ack': 'nok', 'info': 'auction does not exist'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)
            else:

                r_string = ''.join(
                    random.choice(string.digits + string.ascii_lowercase + string.ascii_uppercase) for c in range(6))

                msg = {'payload': {'ack': 'ok', 'r_string': r_string, 'numZeros': '5', 'type': type,
                                   'hash_prev': self.hash_prev[data['serial']]}}

                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

                data2, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                data2 = json.loads(data2)

                signature = base64.b64decode(data2['signature'])
                if self.crypto.verifySignatureCC(self.pubkey_dict[data2['payload']['id']],
                                                 json.dumps(data2['payload']), signature):

                    if 'digest' in data2['payload']:
                        print("> proof-of-work result of client: " + json.dumps(data2['payload']['digest']))

                        hash_object = hashlib.sha256(data2['payload']['string'].encode('utf-8'))
                        digest = hash_object.hexdigest()

                        if data2['payload']['digest'] == digest:
                            msg2 = {'payload': {'ack': 'ok', 'type': type, 'hash_prev': self.hash_prev[data['serial']]}}
                            self.current_client = addr
                            self.client_waiting = True
                        else:
                            msg2 = {'payload': {'ack': 'nok'}}
                        signature = base64.b64encode(self.certgen.signData(json.dumps(msg2['payload']))).decode()
                        msg2['signature'] = signature
                        bytes = self.sock.sendto(json.dumps(msg2).encode(), address_client)
                    else:
                        msg2 = {'payload': {'ack': 'nok', 'info': 'busy: could not send proof-of-work'}}

                        signature = base64.b64encode(self.certgen.signData(json.dumps(msg2['payload']))).decode()
                        msg2['signature'] = signature
                        bytes = self.sock.sendto(json.dumps(msg2).encode(), address_client)


        except:
            print("Cannot send proof-of-work to client")
            self.mylogger.log(INFO, "Cannot send proof-of-work to client ")
            raise

    def place_bid(self, addr, data):
        """
        Receives the new bid parameters, creates a new block and
        inserts it in the blockchain of the respective auction
        """
        try:
            self.mylogger.log(INFO, "Place a bid ")
            client_address = addr
            for auction in self.active_auctions:
                if data['bid']['serial'] == str(auction.serial):
                    block = Block(data['bid']['key'], data['bid']['cert'], data['bid']['serial'], data['bid']['hash'],
                                  data['bid']['hash_prev'], data['bid']['amount'], data['bid']['name'],
                                  data['bid']['id'], data['bid']['timestamp'])

                    self.hash_prev[data['bid']['serial']] = data['bid']['hash']

                    msg = {'payload': {'bid_valid': data}}
                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature

                    bytes = self.sock.sendto(json.dumps(msg).encode(), self.manager_address)

                    data2, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                    data2 = json.loads(data2)

                    signature = base64.b64decode(data2['signature'])
                    payload = json.dumps(data2['payload'])

                    if self.valid_signature(self.man_pubkey, payload, signature):
                        if data2['payload']['valid'] is True:
                            auction.add_block(block)
                            print("> bid creation in auction {}: OK".format(auction.serial))

                            signature = base64.b64encode(self.certgen.signData(json.dumps(data2['payload']['receipt']))).decode()
                            data2['payload']['receipt']['sig_r'] = signature

                            msg = {'payload': {'ack': 'ok', 'receipt': data2['payload']['receipt']}}

                            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                            msg['signature'] = signature

                            bytes = self.sock.sendto(json.dumps(msg).encode(), client_address)
                            break
                        else:
                            print("> bid creation in auction {}: NOK".format(auction.serial))

                            if 'info' in data2['payload']:
                                msg = {'payload': {'ack': 'nok', 'info': data2['payload']['info']}}
                            else:
                                msg = {'payload': {'ack': 'nok', 'valid': data2['payload']['valid']}}

                            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                            msg['signature'] = signature
                            bytes = self.sock.sendto(json.dumps(msg).encode(), client_address)
                            break
                else:
                    print("> bid creation in auction {}: NOK".format(auction.serial))
                    msg = {'payload': {'ack': 'nok', 'info': 'non active'}}

                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature
                    bytes = self.sock.sendto(json.dumps(msg).encode(), client_address)

        except:
            print("Cannot create bid")
            self.mylogger.log(INFO, "Cannot create bid ")
            raise

    def list_ids(self, address_client):
        """
        Send list of the IDs of the clients of the system
        """
        try:
            self.mylogger.log(INFO, "Listing active auctions")

            if self.pubkey_dict:
                msg = {'payload': {'ack': 'ok', 'ids': list(self.pubkey_dict.keys())}}
            else:
                msg =  msg = {'payload': {'ack': 'nok'}}

            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

        except:
            self.mylogger.log(INFO, "Cannot list ids of clients")
            raise

    def list_open(self, address_client):
        """
        Send list of the currently active auctions
        """
        try:
            self.mylogger.log(INFO, "Listing active auctions")
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
            print("Cannot send active auctions")
            self.mylogger.log(INFO, "Cannot send active auctions ")
            raise

    def list_closed(self, address_client):
        """
        Send list of the closed auctions
        """
        try:
            self.mylogger.log(INFO, "Listing closed auctions ")
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
            self.mylogger.log(INFO, "Cannot send active auctions ")
            raise

    def bids_auction(self, address_client, serial):
        """
        Send list of all the bids of an auction
        """
        try:
            self.mylogger.log(INFO, "Listing bids of auction {} ".format(serial))
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
            self.mylogger.log(INFO, "Cannot list bids of auction {}".format(serial))
            raise

    def bids_client(self, address_client, id):
        """
        Send list of all the bids of a client
        """
        try:
            self.mylogger.log(INFO, "Listing bids of client {} ".format(id))
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
            self.mylogger.log(INFO, "Listing bids of client {} ".format(id))
            raise

    def check_receipt(self, address_client, serial, hash):
        """
        Send bid information to a client requesting it, for
        validation against a receipt.
        """
        try:
            self.mylogger.log(INFO, "Sending bid information for receipt validation ")
            print("> sending bid information for receipt validation")
            closed_auctions = False

            for auction in self.closed_auctions:
                if str(auction.serial) == serial:
                    closed_auctions = True
                    info = auction.bid_info(hash)

                    if info != "":
                        msg = {'payload': {'bid': info}}
                    else:
                        msg = {'payload': {'ack': 'nok', 'info': 'no info about bid'}}

                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature
                    bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

                else:
                    msg = {'payload': {'ack': 'nok', 'info': 'the auction is not closed'}}

                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature
                    bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)

            if not closed_auctions:
                msg = {'payload': {'ack': 'nok', 'info': 'no closed auctions'}}

                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), address_client)


        except:
            print("> cannot send bid information for receipt validation")
            self.mylogger.log(INFO, "Cannot send bid information for receipt validation ")

    def client_login(self, message, client_addr):
        """
        Storing information on a new client of the system
        """
        try:
            self.mylogger.log(INFO, "Adding new client ")
            cert = None
            if 'c_pubk' in message:
                self.mylogger.log(INFO, "Client Pubkey : \n{}".format(message['c_pubk']))
                self.loggedInClient += 1
                self.pubkey_dict[message['id']] = message['c_pubk']
                self.address_client.append(client_addr)
        except:
            print("Cannot sign up new client")
            self.mylogger.log(INFO, "Cannot signup new client ")
            raise

    def valid_signature(self, pubk, message, signature):
        """
        Validate an entity's signature on a message
        """
        try:
            pubk = self.crypto.loadPubk(pubk)
            if not self.crypto.verifySignatureServers(pubk, message, signature):
                return False
            return True
        except:
            print("Cannot validate signature")
            self.mylogger.log(INFO, "Cannot validate signature ")
            raise

    def exit(self, type):
        """
        Shutdown the repository
        """
        try:
            self.mylogger.log(INFO, "Exiting repository ")
            print("Exiting...")
            self.sock.close()
            sys.exit(type)
        except:
            self.mylogger.log(INFO, "Cannot exit repository ")
            raise


if __name__ == "__main__":
    r = Repository(HOST, PORT_REPO)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
