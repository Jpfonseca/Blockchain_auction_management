import copy
import json, random, string, sys, base64, datetime
from socket import *

from logging import DEBUG, ERROR, INFO

from log import LoggyLogglyMcface
from cc_interface import PortugueseCitizenCard
from security import CertificateOperations, CryptoUtils

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

HOST = "127.0.0.1"
# port client uses to communicate with client
PORT_MAN = 8080
PORT_REPO = 8081

MAX_BUFFER_SIZE = 10000


class Client:
    def __init__(self, host, port_man, port_repo):

        self.mylogger = LoggyLogglyMcface(name=Client.__name__)
        self.mylogger.log(INFO, "Entering Client interface")

        self.host = host
        self.port_man = port_man
        self.port_repo = port_repo

        # public keys
        self.client_cert = None
        self.client_pubk = None
        self.man_pubkey = None
        self.repo_pubkey = None

        # auction and bid symmetric key associated to serial and hash
        self.auction_keys = {}
        self.bid_keys = {}

        # id (and name of the client)
        self.id = None
        self.name = None
        # addresses of the servers
        self.repo_address = None
        self.man_address = None
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        # active auctions
        self.active_auctions = []
        # portuguese citizen card instance
        self.cc = PortugueseCitizenCard()
        self.crypto = CryptoUtils()
        self.slot = -1

    # servers and client exchange public keys
    def start(self):
        # ask user which slot to use
        fullnames = self.cc.getSmartcardsNames()

        slot = -1
        if len(self.cc.sessions) > 0:
            temp = ''.join('Slot{:3d}-> Fullname: {:10s}\n'.format(i, fullnames[i]) for i in range(0, len(fullnames)))

            while slot < 0 or slot > len(self.cc.sessions):
                slot = input("Available Slots: \n{:40s} \n\nWhich Slot do you wish to use? ".format(temp))
                if slot.isdigit():
                    slot = int(slot)
                else:
                    slot = -1
            self.slot = slot

        # close sessions for other slots
        for i in range(0, len(self.cc.sessions)):
            if slot != i:
                self.cc.sessions[i].closeSession()

        # get cc certificate (bytes)
        cert = self.cc.PTEID_GetCertificate(self.slot)
        self.client_cert = cert

        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        digest.update(self.cc.PTEID_GetBI(slot).encode())
        self.id = base64.b64encode(digest.finalize()).decode()

        self.mylogger.log(INFO, "Client ID: {}".format(self.id))

        # calculate md5 digest of the citizen card number (id of the user)
        certop = CertificateOperations()
        certop.getCertfromPem(cert)
        self.client_pubk = certop.getPubKey().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # send client certificate and id to repository
        msg = json.dumps({'c_pubk': self.client_pubk.decode(), 'id': self.id})
        self.mylogger.log(INFO, "Exchanging pubkey's with the Repo")
        bytes = self.sock.sendto(msg.encode(), (self.host, self.port_repo))
        data1, address = self.sock.recvfrom(MAX_BUFFER_SIZE)
        print("> repository pubkey received")
        self.mylogger.log(INFO, "Repo Pubkey received")

        # send client certificate and id to manager
        self.mylogger.log(INFO, "Exchanging pubkey with the Manager")
        bytes = self.sock.sendto(msg.encode(), (self.host, self.port_man))
        data2, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
        print("> manager pubkey received")
        self.mylogger.log(INFO, "Manager Pubkey received")

        data1 = json.loads(data1)
        data2 = json.loads(data2)

        # store repository and manager public key in global variable
        # self.repo_pubkey = base64.b64decode(data1['repo_pubk']).decode()
        # self.man_pubkey = base64.b64decode(data2['man_pubk']).decode()
        self.repo_pubkey = data1['repo_pubk']
        self.man_pubkey = data2['man_pubk']

        # the client's certificate is invalid
        if 'err' in data1:
            print("Invalid Certificate")
            sys.exit(-1)
        # save the repository and manager address
        if 'repo_pubk' in data1:
            self.repo_address = address
        if 'man_pubk' in data2:
            self.man_address = server

        self.mylogger.log(INFO, "Repo Pubkey : \n{}\nManager Pubkey : \n{}".format(self.repo_pubkey, self.man_pubkey))
        self.loop()

    # menu of the client
    def loop(self):
        self.mylogger.log(INFO, "Entered Client Menu")
        while (True):
            print("\n----Menu----\n1) Create auction\n2) Place bid\n3) Check receipt\n4) List active auctions\n"
                  "5) List closed auctions\n6) Display bids of an auction\n7) Display bids of a client\n8) Validate"
                  " receipt\n9) Display my information\n10) Close")

            option = input(">")

            if option == '1':
                self.create_auction()
            elif option == '2':
                self.place_bid()
            elif option == '3':
                self.check_receipt()
            elif option == '4':
                self.list_active_auctions()
            elif option == '5':
                self.list_closed_auctions()
            elif option == '6':
                self.bids_auction()
            elif option == '7':
                self.bids_client()
            elif option == '8':
                self.validate_receipt()
            elif option == '9':
                self.display_client()
            elif option == '10':
                msg = json.dumps({'payload': {'exit': 'client exit'}})
                sent = self.sock.sendto(msg.encode(), self.man_address)
                sent = self.sock.sendto(msg.encode(), self.repo_address)
                # remove files
                self.mylogger.log(INFO, "Exiting Client")

                sys.exit()
            else:
                print("Not a valid option!\n")

    # send new auction parameters to manager - done
    def create_auction(self):
        try:
            self.mylogger.log(INFO, "Creating auction")

            name = input("Name: ")
            time_limit = input("Time limit: ")  # format: 0h0m30s
            description = input("Description: ")
            type_auction = input("(e)nglish or (b)lind):")
            bidders = input("Limit to bidders:")  # format: 1,2,3...
            limit_bids = input("Limit bids of a bidder:")  # format: 1:2, 2:3

            date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

            key = Fernet.generate_key()
            f = Fernet(key)

            # cert = base64.b64encode(self.client_cert).decode()
            # certs and symmetric keys are saved in base64 format
            encryptedSymCert = base64.b64encode(f.encrypt(self.client_cert)).decode()
            encryptedSymKey = base64.b64encode(
                self.crypto.RSAEncryptData(self.crypto.loadPubk(self.man_pubkey), key)).decode()

            if bidders and not limit_bids:
                msg = {'payload': {'auction': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': None,
                                               'id': self.id, 'timestamp': date_time, 'name': name,
                                               'time-limit': time_limit,
                                               'description': description, 'type': type_auction, 'bidders': bidders}}}
            elif limit_bids and not bidders:
                msg = {'payload': {'auction': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': None,
                                               'id': self.id, 'timestamp': date_time, 'name': name,
                                               'time-limit': time_limit,
                                               'description': description, 'type': type_auction,
                                               'limit_bids': limit_bids}}}
            elif bidders and limit_bids:
                msg = {'payload': {'auction': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': None,
                                               'id': self.id, 'timestamp': date_time, 'name': name,
                                               'time-limit': time_limit,
                                               'description': description, 'type': type_auction, 'bidders': bidders,
                                               'limit_bids': limit_bids}}}
            else:
                msg = {'payload': {'auction': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': None,
                                               'id': self.id, 'timestamp': date_time, 'name': name,
                                               'time-limit': time_limit,
                                               'description': description, 'type': type_auction}}}

            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()

            msg['signature'] = signature
            msg = json.dumps(msg)
            # size = sys.getsizeof(msg.encode())
            bytes = self.sock.sendto(msg.encode(), (self.host, self.port_man))
            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)

            data = json.loads(data)
            signature = base64.b64decode(data['signature'])
            ack = json.dumps(data['payload'])

            if self.validSignature(self.man_pubkey, ack, signature):
                if data['payload']['ack'] == 'ok':
                    # store the symmetric key of the current auction
                    self.auction_keys[data['payload']['serial']] = key
                    print("\nNew auction created!")
                else:
                    print("The auction was NOT created. Error: {}".format(data['payload']['info']))
                    msg = json.dumps({'payload': {'exit': 'client exit'}})
                    sent = self.sock.sendto(msg.encode(), self.man_address)
                    sent = self.sock.sendto(msg.encode(), self.repo_address)
                    c.mylogger.log(INFO, "Exiting Client")
                    print("Exiting...")
                    sys.exit(-1)
            else:
                print("Manager Pubk not verified")
                msg = json.dumps({'payload': {'exit': 'client exit'}})
                sent = self.sock.sendto(msg.encode(), self.man_address)
                sent = self.sock.sendto(msg.encode(), self.repo_address)
                c.mylogger.log(INFO, "Exiting Client")
                print("Exiting...")
                sys.exit(-1)
        except:
            raise Exception("Cannot contact the manager")

    # request a bid, calculate proof-of-work, send parameters to repository
    def place_bid(self):
        try:
            self.mylogger.log(INFO, "Placing bid ")
            serial = input("Serial number of auction:")
            amount = input("Amount: ")

            # request bid creation and wait for proof-of-work parameter
            msg = {'payload': {'command': 'bid_request', 'id': self.id, 'serial': serial}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            # validate repo signature and send bid parameters
            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])
            if self.validSignature(self.repo_pubkey, payload, signature):

                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("Auction requested does not exist")

                else:
                    # calculate proof-of-work
                    answer = self.get_pow(data['payload']['size'])

                    # encrypt cert with symmetric key and symmetric key with manager pubkey
                    bid_key = Fernet.generate_key()
                    f = Fernet(bid_key)

                    # certs and symmetric keys are saved in base64 format
                    encryptedSymCert = base64.b64encode(f.encrypt(self.client_cert)).decode()
                    encryptedSymKey = base64.b64encode(
                        self.crypto.RSAEncryptData(self.crypto.loadPubk(self.man_pubkey), bid_key)).decode()

                    # send bid parameters depending on auction type
                    type = data['payload']['type']
                    # time of creation of bid
                    date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

                    if type == 'e':
                        msg = {'payload': {'bid': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': serial,
                                                   'hash': answer, 'hash_prev': data['payload']['hash_prev'],
                                                   'amount': amount, 'name': "", 'id': self.id, 'timestamp': date_time}}}

                    elif type == 'b':
                        encryptedAmount = base64.b64encode(f.encrypt(amount.encode())).decode()
                        msg = {'payload': {'bid': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': serial,
                                                   'hash': answer, 'hash_prev': data['payload']['hash_prev'],
                                                   'amount': encryptedAmount, 'name': "", 'id': self.id,
                                                   'timestamp': date_time}}}

                    signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
                    msg['payload']['sig_c'] = signature

                    # {'payload': {'bid': {...}, 'sig_c': signature}, 'signature': signature}
                    bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

                    # receive ack or nack of the bid creation
                    data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
                    data = json.loads(data)

                    signature = base64.b64decode(data['signature'])
                    payload = json.dumps(data['payload'])
                    if self.validSignature(self.repo_pubkey, payload, signature):
                        if data['payload']['ack'] == 'ok':

                            repo_valid = False
                            manager_valid = False
                            client_valid = False

                            # validate received receipt and store it in a file
                            print("Receipt validation:")
                            data_v = copy.deepcopy(data['payload']['receipt'])

                            # verify repository signature
                            signature = base64.b64decode(data_v.pop('sig_r'))
                            if self.validSignature(self.repo_pubkey, json.dumps(data_v), signature):
                                repo_valid = True
                                print("Repository's signature -> valid")

                            # verify manager signature
                            signature = base64.b64decode(data_v.pop('sig_m'))
                            if self.validSignature(self.man_pubkey, json.dumps(data_v), signature):
                                manager_valid = True
                                print("Manager's signature -> valid")

                            # verify client signature
                            signature = base64.b64decode(data_v.pop('sig_c'))
                            if self.crypto.verifySignatureCC(self.client_pubk, json.dumps(data_v), signature):
                                client_valid = True
                                print("Client's signature -> valid")

                            if repo_valid and manager_valid and client_valid:
                                if serial not in self.bid_keys:
                                    self.bid_keys[serial] = {str(answer): bid_key}
                                else:
                                    self.bid_keys[serial][str(answer)] = bid_key
                                print("\nBid created successfully")
                            else:
                                print("Receipt signatures are not valid. Exiting compromised system...")
                                sys.exit(-1)
                        else:
                            print("\nBid not created")
        except:
            print("Bid was not created")
            raise

    # verify if the receipt corresponds to the information retrieved from the repository
    def check_receipt(self):
        self.mylogger.log(INFO, "Checking Receipt ")
        msg = json.dumps({'command': 'check_receipt', 'signature': 'oi'})
        bytes = self.sock.sendto(msg.encode(), self.repo_address)
        data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)

    # list active auctions
    def list_active_auctions(self):
        try:
            self.mylogger.log(INFO, "Listing active auctions ")
            msg = {'payload': {'command': 'list_open', 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature

            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)
            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.validSignature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("\nNo active auctions at the moment")
                else:
                    print(data['payload'])
        except:
            print("Can't list active auctions")
            self.mylogger.log(INFO, "Can't list active auctions")
            raise

    # list closed auctions
    def list_closed_auctions(self):
        try:
            self.mylogger.log(INFO, "Listing closed auctions ")
            msg = {'payload': {'command': 'list_closed', 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature

            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)
            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.validSignature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("\nNo closed auctions at the moment")
                else:
                    print(data['payload'])
        except:
            print("Can't list closed auctions")
            self.mylogger.log(INFO, "Can't list closed auctions")
            raise

    # list all bids of an auction
    def bids_auction(self):
        try:
            serial = input("Serial number of auction:")

            msg = {'payload': {'command': 'bid_auction', 'serial': serial, 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.validSignature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("Auction has no bids")
                else:
                    print("\nBids of auction {}:".format(serial))
                    for key in data['payload'].keys():
                        print(data['payload'][key] + "\n")
        except:
            print("Cannot list of bids of an auction")
            raise

    # list all bids of a client
    def bids_client(self):
        try:
            id = input("Id of the client:")

            msg = {'payload': {'command': 'bid_client', 'c_id': id, 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.validSignature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("Client has no bids")
                else:
                    print("\nBids of client {}:".format(id))
                    for key in data['payload'].keys():
                        print(data['payload'][key] + "\n")

        except:
            print("Cannot show bids of auction")
            raise

    def validate_receipt(self):
        print("Validating receipt")

    # def validate_receipt()

    def display_client(self):
        print("Name: {}, Id: {}".format(self.name, self.id))

    # generate string with length = size
    def gen_string(self, size):
        self.mylogger.log(INFO, "Generating string")
        answer = ''.join(
            random.choice(string.digits + string.ascii_lowercase + string.ascii_uppercase) for c in range(size))
        return answer

    # calculate the proof-of-work result
    def get_pow(self, size):
        self.mylogger.log(INFO, "Calculating proof-of-work with size {}".format(size))

        result = False
        solution = None

        print("\n...calculating proof-of-work with size {}".format(size))

        while result is False:
            solution = self.gen_string(int(size))

            if solution.startswith("11"):
                print("Answer: {}\n".format(solution))
                result = True

        return solution

    def validSignature(self, pubk, message, signature):
        try:
            pubk = self.crypto.loadPubk(pubk)
            if not self.crypto.verifySignatureServers(pubk, message, signature):
                return False
            return True
        except:
            print("Cannot validate signature")
            raise

    # shutdown the socket
    def close(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


if __name__ == "__main__":

    c = Client(HOST, PORT_MAN, PORT_REPO)

    try:
        c.start()
    except KeyboardInterrupt:
        msg = json.dumps({'exit': 'client exit'})
        sent = c.sock.sendto(msg.encode(), c.man_address)
        sent = c.sock.sendto(msg.encode(), c.repo_address)
        c.mylogger.log(INFO, "Exiting Client")
        print("Exiting...")
        c.close()
