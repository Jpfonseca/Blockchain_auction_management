import base64
import json
import sys
from socket import *
from blockchain import *
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
        # list of addresses
        self.address_client = []
        self.repo_address = None
        # list of active and closed auctions (blockchain dictionary)
        self.active_auctions = []
        self.closed_auctions = []
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # generate public and private key
        self.certgen = GenerateCertificates()
        self.crypto = CryptoUtils()
        self.cc = PortugueseCitizenCard()
        self.certops = CertificateOperations()

        # dictionary with id and address
        self.clients_address = {}
        # dictionary of number of bids per bidder in an auction
        self.bid_number = {}
        # dictionary with keys and certs associated with auctioner and bidders
        # self.certs_dic = {}
        # dictionary with serial of auction and previous amount bidded
        self.auction_amount = {}

    # server and client exchange public keys
    def start(self):
        try:
            # verify if manager private key already exists. load if true
            if self.certgen.checkExistence(self.name):
                self.certgen.loadPrivateKeyFromFile(self.privKname, password=self.password)
            else:
                self.certgen.writePrivateKeyToFile(self.privKname, password=self.password)

            self.privateKey = self.certgen.privateKey
            # get public key of manager and store to global variable
            self.man_pubkey = self.certgen.publicKeyToBytes()
            # self.man_pubkey = base64.b64encode(self.man_pubkeyb).decode()

            print("Listening...")

            # 1) exchange public keys with the repository
            self.mylogger.log(INFO, "Exchanging public Key with the Repo")
            msg = json.dumps({'man_pubk': self.man_pubkey.decode()})
            bytes = self.sock.sendto(msg.encode(), (self.host, PORT_REPO))
            print("> repository pubkey received")
            data1, self.repo_address = self.sock.recvfrom(MAX_BUFFER_SIZE)
            self.mylogger.log(INFO, "Repo Pubkey received")

            # store the received repository public key in global variable
            data1 = json.loads(data1)
            if 'repo_pubk' in data1:
                self.repo_pubkey = data1['repo_pubk']
            self.mylogger.log(INFO, "Repo Pubkey : \n{}".format(self.repo_pubkey))

            # 2) exchange public key with client
            self.mylogger.log(INFO, "Exchanging public Key with the Client")
            data2, client_addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
            print("> client pubkey received")
            bytes = self.sock.sendto(msg.encode(), client_addr)
            self.mylogger.log(INFO, "Client Pubkey received")

            data2 = json.loads(data2)
            self.client_login(data2, client_addr)

            self.loop()
        except:
            print("Cannot start manager server")
            raise

    # manager waits for client or repository messages
    def loop(self):
        try:
            while (True):
                data, addr = self.sock.recvfrom(MAX_BUFFER_SIZE)
                data2 = json.loads(data)

                # add new client
                if (addr not in self.address_client) and (addr != self.repo_address):
                    print("> client pubkey received")
                    msg = json.dumps({'man_pubk': self.man_pubkey.decode()})
                    bytes = self.sock.sendto(msg.encode(), addr)
                    self.client_login(data2, addr)
                    self.loggedInClient += 1
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
                                # auction was created in repository
                                if data2['payload']['info'] == 'auction':
                                    print("> auction creation: OK")
                                    signature = base64.b64encode(
                                        self.certgen.signData(json.dumps(data2['payload']))).decode()
                                    self.active_auctions[-1]['serial'] = data2['payload']['serial']
                                    data2['signature'] = signature
                                    bytes = self.sock.sendto(json.dumps(data2).encode(),
                                                             self.clients_address[data2['payload']['id']])
                            elif data2['payload']['ack'] == 'nok':
                                # auction was not created on the repository
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
            print("Exception on manager server's loop")
            raise

    def create_auction(self, msg, addr):
        try:
            # {'payload':{'key':key,'cert',cert,'auction':{...}}, 'signature': signature}
            id = msg['payload']['auction']['id']
            self.clients_address[id] = addr

            self.bid_number[msg['payload']['auction']['serial']] = None

            # extract auction parameters
            auction = msg['payload']['auction']
            self.active_auctions.append(auction)

            pubk = self.pubkey_dict[id]
            payload = json.dumps(msg['payload'])
            signature = base64.b64decode(msg['signature'])

            # decrypt symmetric key msg['key'] with manager private key
            encrypted_key = base64.b64decode(msg['payload']['auction']['key'])
            key = self.crypto.RSADecryptData(self.privateKey, encrypted_key)

            # decrypt client's certificate msg['cert']
            f = Fernet(key)
            encrypted_cert = base64.b64decode(msg['payload']['auction']['cert'])
            cert = f.decrypt(encrypted_cert)
            #self.certops.getCertfromPem(cert)
            #cert_pubk = self.certops.getPubKey()
            #cert_pubk = self.certops.rsaPubkToPem(cert_pubk)

            message = {'payload': {'ack': 'nok'}}

            valid = True

            #if not cert_pubk == pubk.encode():
                #message['payload']['info'] = 'diff pubk'
                #valid = False
            #if not self.cc.verifyChainOfTrust(cert):
                #message['payload']['info'] = 'cc cert not verified'
                #valid = False

            if not valid:
                signature = base64.b64encode(self.certgen.signData(json.dumps(message['payload']))).decode()
                message['signature'] = signature
                bytes = self.sock.sendto(json.dumps(message).encode(), addr)
            else:
                print("> valid client's signature")
                self.mylogger.log(INFO, "Verified Client Payload :\n{}".format(payload))

                auction = msg['payload']['auction']
                msg = {'payload': {'auction': auction, 'valid': valid}}

                signature = self.certgen.signData(json.dumps(msg['payload']))
                signature = base64.b64encode(signature).decode()

                msg['signature'] = signature

                # send: auction + validation of client's certificate + signature
                bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)
        except:
            print("Cannot create auction")
            raise

    def validate_bid(self, data, addr):
        try:
            # check if certificate is valid
            for auction in self.active_auctions:
                if str(auction['serial']) == str(data['bid']['serial']):

                    # decrypt symmetric key msg['key'] with manager private key
                    encrypted_key = base64.b64decode(data['bid']['key'])
                    key = self.crypto.RSADecryptData(self.privateKey, encrypted_key)

                    # decrypt client's certificate msg['cert']
                    f = Fernet(key)
                    encrypted_cert = base64.b64decode(data['bid']['cert'])
                    cert = f.decrypt(encrypted_cert)

                    # if not self.cc.verifyChainOfTrust(cert):
                    # message['payload']['info'] = 'cc cert not verified'
                    # valid = False

                    # in english auction, check if the current amount bidded is higher than the previous
                    if auction['type'] == 'e':
                        if data['bid']['serial'] not in self.auction_amount:
                            self.auction_amount[data['bid']['serial']] = data['bid']['amount']
                        else:
                            previous_amount = self.auction_amount[data['bid']['serial']]
                            self.auction_amount[data['bid']['serial']] = data['bid']['amount']

                            if int(self.auction_amount[data['bid']['serial']]) < int(previous_amount):
                                msg = {'payload': {'valid': False}}
                                signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                                msg['signature'] = signature
                                sent = self.sock.sendto(json.dumps(msg).encode(), addr)

                    valid = False
                    if 'bidders' in auction or 'limit_bids' in auction:
                        # bidders: limit number of bidders to certain identities
                        bidders = auction['bidders'].split(',')  # format: ['1','2',...]

                        # limit_bids = limit number of bids performed by each identity
                        limit_bids = auction['limit_bids'].split(',')  # format: ['1:2','2:3'...]

                        # bid_number: bids performed by the current identity, in the current auction
                        if self.bid_number[data['bid']['serial']] is None:
                            self.bid_number[data['bid']['serial']]['id'] = 0
                            bid_number = 0
                        else:
                            self.bid_number[data['bid']['serial']]['id'] += 1
                            bid_number = self.bid_number[data['bid']['serial']][data['bid']['id']]

                        # validate bid with API
                        valid = True

                    # Mudar o true daqui quando tiver a API

                    # sign the receipt
                    signature = base64.b64encode(self.certgen.signData(json.dumps(data))).decode()
                    data['sig_m'] = signature

                    msg = {'payload': {'valid': True, 'receipt': data}}

                    signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()
                    msg['signature'] = signature
                    sent = self.sock.sendto(json.dumps(msg).encode(), addr)
        except:
            print("Cannot validate bid")
            raise

    def get_winner(self, data):
        try:
            winner_dict = {}
            result = []
            serial = 0

            print("> auction ended")

            # load the auction file and calculate the winner
            with open(data['end']) as f:
                lines = f.readlines()

            auction = lines.pop(0)
            auction_dict = literal_eval(auction)
            type = auction_dict['type']
            serial = auction_dict['serial']

            for line in lines:
                line = line[:-1]
                bid = literal_eval(line)

                # decrypt symmetric key bid['key'] with manager private key
                encrypted_key = base64.b64decode(bid['key'])
                key = self.crypto.RSADecryptData(self.privateKey, encrypted_key)

                # decrypt client's certificate
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

                # add the current bid to the result list (that will saved to the file)
                result.append(str(bid))

            result = zip(winner_dict.values(), winner_dict.keys())

            # Converting itertor to list
            result = list(result)

            if result:
                # calculate the winner of the auction
                winner = max(zip)

                # store the identity of the winner in the auction
                auction_dict['winner'] = winner[1]
                auction_dict['winner_amount'] = winner[0]
                auction_dict['state'] = 'closed'

                result.append(str(auction_dict))

                # escreve a auction e as bids para o ficheiro
                with open(data['end'], 'w') as f:
                    # the last element of the list is the auction
                    f.write("%s\n" % result[-1])

                    result.remove(result[-1])

                    print(result)

                    # the other elements of the list are the bids
                    for line in result:
                        f.write("%s\n" % line)

                # the winner was found and the new blockchain was written to the file
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
            raise

    # verify client's cert, store client's certificate in dictionary with 'id' keys
    def client_login(self, message, client_addr):
        cert = None
        if 'c_pubk' in message:
            self.mylogger.log(INFO, "Client Pubkey : \n{}".format(message['c_pubk']))
            self.loggedInClient += 1
            self.pubkey_dict[message['id']] = message['c_pubk']
            self.address_client.append(client_addr)

    def valid_signature(self, pubk, message, signature):
        try:
            pubk = self.crypto.loadPubk(pubk)
            if not self.crypto.verifySignatureServers(pubk, message, signature):
                return False
            return True
        except:
            print("Cannot validate the signature")
            raise

    # shutdown the socket
    def exit(self, type):
        try:
            self.mylogger.log(INFO, "Exiting Repository")
            print("Exiting...")
            self.sock.close()
            sys.exit(type)
        except:
            print("Cannot exit manager server")
            raise

if __name__ == "__main__":
    r = Manager(HOST, PORT)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")
        raise
