import base64
import json
import sys
from socket import *
from blockchain import *
from validator import Valid
from ast import literal_eval

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface
from security import *

from cryptography.fernet import Fernet
from cc_interface import PortugueseCitizenCard

HOST = "127.0.0.1"
PORT = 8080
PORT_REPO = 8081

MAX_BUFFER_SIZE = 10000


class Manager:
    def __init__(self, host, port):
        self.mylogger = LoggyLogglyMcface(name=Manager.__name__)
        self.mylogger.log(INFO, "Entering Manager interface")

        # manager information
        self.name = Manager.__name__
        self.privKname = "privK" + self.name
        self.password = "1234"
        self.privateKey = None
        self.man_pubkey = None

        self.loggedInClient = 0
        self.host = host
        self.port = port

        # stored public keys
        self.repo_pubkey = None
        self.pubkey_dict = {}

        # list of addresses of clients and repository address
        self.address_client = []
        self.repo_address = None

        # list of active and closed auctions
        self.active_auctions = []
        self.closed_auctions = []

        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

        # generate public and private key
        self.certgen = GenerateCertificates()
        self.crypto = CryptoUtils()
        self.cc = PortugueseCitizenCard()
        self.certops = CertificateOperations()

        # dictionary with id and address of clients
        self.clients_address = {}
        # dictionary of number of bids per bidder in an auction
        self.bid_number = {}
        # dictionary with serial of an auction and previous amount bidded
        self.auction_amount = {}
        # dictionary of the dynamic code associated with each auction
        self.dynamic_code = {}
        self.current_dynamic_code = {}
        # used for validation of the bids
        self.validator = Valid()

    def start(self):
        """
        Servers and Client exchange public keys
        """
        try:
            if self.certgen.checkExistence(self.name):
                self.certgen.loadPrivateKeyFromFile(self.privKname, password=self.password)
            else:
                self.certgen.writePrivateKeyToFile(self.privKname, password=self.password)

            self.privateKey = self.certgen.privateKey
            self.man_pubkey = self.certgen.publicKeyToBytes()

            print("Listening...")

            self.mylogger.log(INFO, "Exchanging public key with the Repo")
            msg = json.dumps({'man_pubk': self.man_pubkey.decode()})
            bytes = self.sock.sendto(msg.encode(), (self.host, PORT_REPO))
            print("> repository pubkey received")
            data1, self.repo_address = self.sock.recvfrom(MAX_BUFFER_SIZE)
            self.mylogger.log(INFO, "Repo public key received")

            data1 = json.loads(data1)
            if 'repo_pubk' in data1:
                self.repo_pubkey = data1['repo_pubk']
            self.mylogger.log(INFO, "Repo Pubkey : \n{}".format(self.repo_pubkey))

            self.mylogger.log(INFO, "Exchanging public key with the Client")
            data2, client_addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
            print("> client pubkey received")
            bytes = self.sock.sendto(msg.encode(), client_addr)
            self.mylogger.log(INFO, "Client public key received")

            data2 = json.loads(data2)
            self.client_login(data2, client_addr)

            self.loop()
        except:
            self.mylogger.log(INFO, "Cannot start manager")
            raise

    def loop(self):
        """
        The main loop of the manager. It waits for messages of clients
        (both system clients or servers) and calls functions according
        to the received messages
        """
        try:
            while (True):
                data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                data2 = json.loads(data)

                if (addr not in self.address_client) and (addr != self.repo_address):
                    self.mylogger.log(INFO, "Adding new client ")
                    print("> client pubkey received")
                    msg = json.dumps({'man_pubk': self.man_pubkey.decode()})
                    bytes = self.sock.sendto(msg.encode(), addr)
                    self.client_login(data2, addr)

                else:
                    if 'auction' in data2['payload']:
                        signature = base64.b64decode(data2['signature'])
                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['payload']['auction']['id']],
                                                         json.dumps(data2['payload']), signature):
                            self.create_auction(data2, addr)

                    if 'bid_valid' in data2['payload']:
                        signature = base64.b64decode(data2['signature'])
                        if self.valid_signature(self.repo_pubkey, json.dumps(data2['payload']), signature):
                            self.validate_bid(data2['payload']['bid_valid'], addr)

                    if 'ack' in data2['payload']:
                        signature = base64.b64decode(data2['signature'])

                        if self.valid_signature(self.repo_pubkey, json.dumps(data2['payload']), signature):
                            if data2['payload']['ack'] == 'ok':
                                if data2['payload']['info'] == 'auction':
                                    print("> auction creation: OK")

                                    self.dynamic_code[data2['payload']['serial']] = self.current_dynamic_code

                                    signature = base64.b64encode(
                                        self.certgen.signData(json.dumps(data2['payload']))).decode()
                                    self.active_auctions[-1]['serial'] = data2['payload']['serial']
                                    data2['signature'] = signature
                                    bytes = self.sock.sendto(json.dumps(data2).encode(),
                                                             self.clients_address[data2['payload']['id']])
                            elif data2['payload']['ack'] == 'nok':
                                if data2['payload']['info'] == 'auction':
                                    print("> auction creation: NOT OK")
                                    signature = base64.b64encode(self.certgen.signData(json.dumps(data2['payload'])))
                                    data2['signature'] = signature
                                    bytes = self.sock.sendto(json.dumps(data2).encode(),
                                                             self.clients_address[data2['payload']['id']])

                    if 'end' in data2['payload']:
                        signature = base64.b64decode(data2['signature'])
                        if self.valid_signature(self.repo_pubkey, json.dumps(data2['payload']), signature):
                            self.get_winner(data2['payload'])

                    if 'exit' in data2['payload']:
                        msg = json.dumps({'payload': {'exit': 'client exit'}})
                        signature = base64.b64decode(data2['signature'])

                        if self.crypto.verifySignatureCC(self.pubkey_dict[data2['payload']['id']],
                                                     json.dumps(data2['payload']), signature):
                            self.loggedInClient -= 1
                            if self.loggedInClient <= 0:
                                self.mylogger.log(INFO, "Exiting Manager")
                                self.exit(0)
        except:
            self.mylogger.log(INFO, "Exception on manager's loop")
            raise

    def create_auction(self, msg, addr):
        """
        Receive auction parameters from client and
        request its storage in the repository server
        """
        try:
            self.mylogger.log(INFO, "Receiving auction request")

            id = msg['payload']['auction']['id']
            self.clients_address[id] = addr

            self.current_dynamic_code = msg['payload']['dynamic_code']

            auction = msg['payload']['auction']
            self.active_auctions.append(auction)

            pubk = self.pubkey_dict[id]
            payload = json.dumps(msg['payload'])
            signature = base64.b64decode(msg['signature'])

            encrypted_key = base64.b64decode(msg['payload']['auction']['key'])
            key = self.crypto.RSADecryptData(self.privateKey, encrypted_key)

            f = Fernet(key)
            encrypted_cert = base64.b64decode(msg['payload']['auction']['cert'])
            cert = f.decrypt(encrypted_cert)
            self.certops.getCertfromPem(cert)
            cert_pubk = self.certops.getPubKey()
            cert_pubk = self.certops.rsaPubkToPem(cert_pubk)

            message = {'payload': {'ack': 'nok'}}

            valid = True

            if not cert_pubk == pubk.encode():
                message['payload']['info'] = 'diff pubk'
                valid = False
            if not self.cc.verifyChainOfTrust(cert):
                message['payload']['info'] = 'cc cert not verified'
                valid = False
            else:
                print("Valid certificate")

            if not valid:
                signature = base64.b64encode(self.certgen.signData(json.dumps(message['payload']))).decode()
                message['signature'] = signature
                bytes = self.sock.sendto(json.dumps(message).encode(), addr)
            else:
                print("> valid client's signature")
                self.mylogger.log(INFO, "Verified Client Payload :\n{}".format(payload))

                auction = msg['payload']['auction']
                msg = {'payload': {'auction': auction, 'valid': valid}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)
        except:
            print("Cannot create auction")
            self.mylogger.log(INFO, "Cannot create auction")
            raise

    def validate_bid(self, data, addr):
        """
        Validate a bid, as a request of the repository server
        Here, the function for the execution of the dynamic
        code is called, returning True or False if the bid
        is valid or not.
        """
        try:
            self.mylogger.log(INFO, "Validating bid")

            valid = False

            for auction in self.active_auctions:
                if str(auction['serial']) == str(data['bid']['serial']):

                    encrypted_key = base64.b64decode(data['bid']['key'])
                    key = self.crypto.RSADecryptData(self.privateKey, encrypted_key)

                    f = Fernet(key)
                    encrypted_cert = base64.b64decode(data['bid']['cert'])
                    cert = f.decrypt(encrypted_cert)

                    if not self.cc.verifyChainOfTrust(cert):
                        print("Certificate not valid\n")
                        valid = False
                    else:
                        valid = True
                        print("Valid certificate")

                    if not valid:
                        msg = {'payload': {'valid': valid, 'info': 'cc cert not verified'}}

                    else:
                        if auction['type'] == 'e':
                            if data['bid']['serial'] not in self.auction_amount:
                                self.auction_amount[data['bid']['serial']] = data['bid']['amount']
                            else:
                                previous_amount = self.auction_amount[data['bid']['serial']]
                                self.auction_amount[data['bid']['serial']] = data['bid']['amount']

                                if int(self.auction_amount[data['bid']['serial']]) < int(previous_amount):
                                    msg = {'payload': {'valid': False, 'info': 'amount smaller than previous'}}
                                    signature = base64.b64encode(
                                        self.certgen.signData(json.dumps(msg['payload']))).decode()
                                    msg['signature'] = signature
                                    sent = self.sock.sendto(json.dumps(msg).encode(), addr)

                        id_client = data['bid']['id']
                        serial_auction = auction['serial']

                        if auction['serial'] not in self.bid_number:
                            self.bid_number[auction['serial']] = {}
                            self.bid_number[auction['serial']][data['bid']['id']] = 1
                        elif (auction['serial'] in self.bid_number) and not (
                                data['bid']['id'] in self.bid_number[auction['serial']]):
                            self.bid_number[auction['serial']][data['bid']['id']] = 1
                        else:
                            self.bid_number[auction['serial']][data['bid']['id']] += 1

                        valid = self.validator.dynamic_code(id_client, self.bid_number[serial_auction][id_client],
                                                        self.dynamic_code[str(serial_auction)])
                        signature = base64.b64encode(self.certgen.signData(json.dumps(data))).decode()
                        data['sig_m'] = signature
                        msg = {'payload': {'valid': valid, 'receipt': data, 'info': 'non valid bid'}}

                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature
                    sent = self.sock.sendto(json.dumps(msg).encode(), addr)
        except:
            print("Cannot validate bid")
            self.mylogger.log(INFO, "Cannot validate bid")
            raise

    def get_winner(self, data):
        """
        Read the file of a closed auction and compute the winner,
        which is the client with the higher amount. The outcome
        is stored on the file and then loaded into a linked list
        (blockchain) by the repository server
        """
        try:
            self.mylogger.log(INFO, "Computing winner of the auction")
            winner_dict = {}
            result = []
            serial = 0

            print("> auction ended")

            with open(data['end']) as f:
                lines = f.readlines()

            auction = lines.pop(0)
            auction_dict = literal_eval(auction)
            type = auction_dict['type']
            serial = auction_dict['serial']

            for line in lines:
                line = line[:-1]
                bid = literal_eval(line)

                encrypted_key = base64.b64decode(bid['key'])
                key = self.crypto.RSADecryptData(self.privateKey, encrypted_key)

                f = Fernet(key)
                encrypted_cert = base64.b64decode(bid['cert'])
                cert = f.decrypt(encrypted_cert)

                # if auction type is 'b', must also decrypt the amount
                if type == 'b':
                    encrypted_amount = base64.b64decode(bid['amount'])
                    amount = f.decrypt(encrypted_amount).decode()
                    bid['amount'] = amount

                bid['name'] = self.cc.GetNameFromCERT(cert)
                winner_dict[str(bid['name'])] = bid['amount']

                result.append(str(bid))

            if result:
                winner = max(zip(winner_dict.values(), winner_dict.keys()))

                auction_dict['winner'] = winner[1]
                auction_dict['winner_amount'] = winner[0]
                auction_dict['state'] = 'closed'

                result.append(str(auction_dict))

                with open(data['end'], 'w') as f:
                    f.write("%s\n" % result[-1])
                    result.remove(result[-1])

                    for line in result:
                        f.write("%s\n" % line)

                msg = {'payload': {'ack': 'ok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            else:
                print("> no bids on ended auction {} -> no possible winner".format(serial))
                msg = {'payload': {'ack': 'nok'}}
                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                msg['signature'] = signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

        except:
            print("Cannot get winner of the auction")
            self.mylogger.log(INFO, "Cannot get winner of auction")
            raise

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
            print("Cannot validate the signature")
            raise

    def exit(self, type):
        """
        Shutdown the manager
        """
        try:
            self.mylogger.log(INFO, "Exiting Manager")
            print("Exiting...")
            self.sock.close()
            sys.exit(type)
        except:
            self.mylogger.log(INFO, "Cannot exit manager ")
            raise


if __name__ == "__main__":

    r = Manager(HOST, PORT)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
        raise
