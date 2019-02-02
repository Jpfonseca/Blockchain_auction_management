import copy, hashlib, json, random, string, sys, base64, datetime
import os
from ast import literal_eval
from socket import *
from pathlib import Path

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

        # public keys and certificates
        self.client_cert = None
        self.client_pubk = None
        self.man_pubkey = None
        self.repo_pubkey = None

        # symmetric key associated with hash of the bid in an auction
        self.bid_keys = {}
        # my bids
        self.bids = []

        # addresses of the servers
        self.repo_address = None
        self.man_address = None

        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)

        # portuguese citizen card and CryptoUtils instance
        self.cc = PortugueseCitizenCard()
        self.crypto = CryptoUtils()
        self.slot = -1

        # id and name of the client
        self.id = None
        self.name = None

    def start(self):
        """
        Servers and Client exchange public keys
        """
        try:
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

            for i in range(0, len(self.cc.sessions)):
                if slot != i:
                    self.cc.sessions[i].closeSession()

            cert = self.cc.PTEID_GetCertificate(self.slot)
            self.client_cert = cert

            self.name = self.cc.GetNameFromCERT(cert)

            digest = hashes.Hash(hashes.MD5(), backend=default_backend())
            digest.update(self.cc.PTEID_GetBI(slot).encode())
            self.id = base64.b64encode(digest.finalize()).decode()

            self.mylogger.log(INFO, "Client ID: {}".format(self.id))

            # calculate md5 digest of the citizen card number (id of the user)
            certop = CertificateOperations()
            certop.getCertfromPem(cert)
            self.client_pubk = certop.getPubKey().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

            msg = json.dumps({'c_pubk': self.client_pubk.decode(), 'id': self.id})
            self.mylogger.log(INFO, "Exchanging pubkey's with the Repo")
            bytes = self.sock.sendto(msg.encode(), (self.host, self.port_repo))
            data1, address = self.sock.recvfrom(MAX_BUFFER_SIZE)
            print("> repository pubkey received")
            self.mylogger.log(INFO, "Repo Pubkey received")

            self.mylogger.log(INFO, "Exchanging pubkey with the Manager")
            bytes = self.sock.sendto(msg.encode(), (self.host, self.port_man))
            data2, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            print("> manager pubkey received")
            self.mylogger.log(INFO, "Manager Pubkey received")

            data1 = json.loads(data1)
            data2 = json.loads(data2)

            self.repo_pubkey = data1['repo_pubk']
            self.man_pubkey = data2['man_pubk']

            if 'repo_pubk' in data1:
                self.repo_address = address
            if 'man_pubk' in data2:
                self.man_address = server

            self.mylogger.log(INFO, "Repo Pubkey : \n{}\nManager Pubkey : \n{}".format(self.repo_pubkey, self.man_pubkey))
            self.loop()
        except:
            self.mylogger.log(INFO, "Cannot start client")
            raise

    # menu of the client
    def loop(self):
        """
        The main loop of the client. It displays the menu and calls
        functions according to the option selected by the user
        """
        try:
            self.mylogger.log(INFO, "Entered Client Menu ")
            while (True):
                print("\n----Menu----\n1) Create auction\n2) Place bid\n3) List active auctions\n"
                      "4) List closed auctions\n5) Display my bids\n6) Display bids of an auction\n"
                      "7) Display bids of a client\n8) Check receipt\n9) Display my information\n"
                      "10) Display ids of all clients\n11) Close")

                option = input(">")

                if option == '1':
                    self.create_auction()
                elif option == '2':
                    self.place_bid()
                elif option == '3':
                    self.list_active_auctions()
                elif option == '4':
                    self.list_closed_auctions()
                elif option == '5':
                    self.display_bids()
                elif option == '6':
                    self.bids_auction()
                elif option == '7':
                    self.bids_client()
                elif option == '8':
                    self.check_receipt()
                elif option == '9':
                    self.display_client()
                elif option == '10':
                    self.display_ids()
                elif option == '11':
                    self.exit(0)
                else:
                    print("Not a valid option!\n")
        except:
            self.mylogger.log(INFO, "Exception on client's loop")
            raise

    def create_auction(self):
        """
        Send new auction parameters to the manager server and wait for
        an ok or not ok answer
        """
        try:
            self.mylogger.log(INFO, "Creating auction ")

            file_exists = False

            name = input("name: ")
            time_limit = input("time limit: ")  # format: _h_m_s
            description = input("description: ")
            type_auction = input("(e)nglish or (b)lind):")
            file = input("dynamic code to be uploaded:")

            while not file_exists:
                current_path = os.getcwd()
                path = "{}/dynamicCode/{}".format(current_path,file)

                my_file = Path(path)
                if my_file.is_file():
                    file_exists = True
                    with open(path) as f:
                        dynamic_code = f.read()
                        break
                else:
                    print("Nonexistent file")
                    file = input("dynamic code to be uploaded:")

            date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

            key = Fernet.generate_key()
            f = Fernet(key)

            # cert = base64.b64encode(self.client_cert).decode()
            # certs and symmetric keys are saved in base64 format
            encryptedSymCert = base64.b64encode(f.encrypt(self.client_cert)).decode()
            encryptedSymKey = base64.b64encode(
                self.crypto.RSAEncryptData(self.crypto.loadPubk(self.man_pubkey), key)).decode()

            msg = {'payload': {'auction': {'key': encryptedSymKey, 'cert': encryptedSymCert, 'serial': None,
                                           'id': self.id, 'timestamp': date_time, 'name': name,
                                           'time-limit': time_limit,
                                           'description': description, 'type': type_auction}, 'dynamic_code': dynamic_code}}

            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()

            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), (self.host, self.port_man))
            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)

            data = json.loads(data)
            signature = base64.b64decode(data['signature'])
            ack = json.dumps(data['payload'])

            if self.valid_signature(self.man_pubkey, ack, signature):
                if data['payload']['ack'] == 'ok':
                    print("\nNew auction created!")
                else:
                    print("The auction was NOT created. Error: {}".format(data['payload']['info']))
                    self.exit(1)
            else:
                print("Manager pubkey not verified")
                self.exit(1)
        except:
            # print("Cannot create auction")
            self.mylogger.log(INFO, "Cannot create auction")
            raise

    # request a bid, calculate proof-of-work, send parameters to repository
    def place_bid(self):
        """
        Send a bid request to the repository server, which answers with a proof-of-work.
        The client computes the proof-of-work, sends the answer to the repository and if
        it is accepted, he/she may send the bid parameters. The repository acknowledges
        the bid by sending a receipt signed by the 3 entities
        """
        try:
            self.mylogger.log(INFO, "Placing bid ")
            serial = input("Serial number of auction:")
            amount = input("Amount: ")

            msg = {'payload': {'command': 'bid_request', 'id': self.id, 'serial': serial}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])
            if self.valid_signature(self.repo_pubkey, payload, signature):

                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        if 'info' in data['payload']:
                            print(data['payload']['info'])

                    else:
                        string, digest = self.hash_cash(data['payload']['r_string'], int(data['payload']['numZeros']))

                        print("Digest: " + digest)

                        msg = {'payload': {'string': string, 'digest': digest, 'id': self.id}}
                        signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
                        msg['signature'] = signature
                        bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

                        data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
                        data = json.loads(data)

                        signature = base64.b64decode(data['signature'])
                        payload = json.dumps(data['payload'])
                        if self.valid_signature(self.repo_pubkey, payload, signature):
                            if data['payload']['ack'] == 'ok':
                                print("Cryptopuzzle result accepted by the server")

                                bid_key = Fernet.generate_key()
                                f = Fernet(bid_key)

                                encrypted_cert = base64.b64encode(f.encrypt(self.client_cert)).decode()
                                encrypted_key = base64.b64encode(
                                    self.crypto.RSAEncryptData(self.crypto.loadPubk(self.man_pubkey), bid_key)).decode()

                                type = data['payload']['type']

                                date_time = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

                                hash_str = str(encrypted_key) + str(encrypted_cert) + str(serial) + \
                                    str(data['payload']['hash_prev']) + str(amount) + str(self.name) + str(self.id) + \
                                    str(date_time)

                                hash = hashlib.md5(hash_str.encode()).hexdigest()

                                self.bids.append(json.dumps({'serial': str(serial), 'hash': str(hash),
                                                             'hash_prev': str(data['payload']['hash_prev']),
                                                             'amount': str(amount), 'name': str(self.name),
                                                             'id': str(self.id), 'timestamp': str(date_time)}))

                                if type == 'e':
                                    msg = {'payload': {'bid': {'key': encrypted_key, 'cert': encrypted_cert, 'serial': serial,
                                                               'hash': hash, 'hash_prev': data['payload']['hash_prev'],
                                                               'amount': amount, 'name': "", 'id': self.id, 'timestamp': date_time}}}

                                elif type == 'b':
                                    encrypted_amount = base64.b64encode(f.encrypt(amount.encode())).decode()
                                    msg = {'payload': {'bid': {'key': encrypted_key, 'cert': encrypted_cert, 'serial': serial,
                                                               'hash': hash, 'hash_prev': data['payload']['hash_prev'],
                                                               'amount': encrypted_amount, 'name': "", 'id': self.id,
                                                               'timestamp': date_time}}}

                                signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
                                msg['payload']['sig_c'] = signature

                                bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

                                data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
                                data = json.loads(data)

                                signature = base64.b64decode(data['signature'])
                                payload = json.dumps(data['payload'])
                                if self.valid_signature(self.repo_pubkey, payload, signature):
                                    if data['payload']['ack'] == 'ok':

                                        repo_valid = False
                                        manager_valid = False
                                        client_valid = False

                                        print("\nReceipt validation:")
                                        data_v = copy.deepcopy(data['payload']['receipt'])

                                        signature = base64.b64decode(data_v.pop('sig_r'))
                                        if self.valid_signature(self.repo_pubkey, json.dumps(data_v), signature):
                                            repo_valid = True
                                            print("Repository's signature -> valid")

                                        signature = base64.b64decode(data_v.pop('sig_m'))
                                        if self.valid_signature(self.man_pubkey, json.dumps(data_v), signature):
                                            manager_valid = True
                                            print("Manager's signature -> valid")

                                        signature = base64.b64decode(data_v.pop('sig_c'))
                                        if self.crypto.verifySignatureCC(self.client_pubk, json.dumps(data_v), signature):
                                            client_valid = True
                                            print("Client's signature -> valid")

                                        if repo_valid and manager_valid and client_valid:
                                            if serial not in self.bid_keys:
                                                self.bid_keys[serial] = {str(hash): bid_key}
                                            else:
                                                self.bid_keys[serial][str(hash)] = bid_key

                                            current_path = os.getcwd()
                                            file = "auction_{}_bid_{}.txt".format(serial, hash)
                                            path = "{}/receipts/{}".format(current_path, file)
                                            text_file = open(path, "w")
                                            text_file.write("%s\n" % json.dumps(data['payload']['receipt']))

                                            print("\nBid created successfully")
                                        else:
                                            print("Receipt signatures are not valid. Exiting compromised system...")
                                            sys.exit(-1)
                                    else:
                                        print("\nBid not created")
                                        self.mylogger.log(INFO, "Bid was not created")
                                        if 'info' in data['payload']:
                                            print("info: " + data['payload']['info'])
                                        else:
                                            print("valid bid: " + str(data['payload']['valid']))
                            else:
                                print("\n Bid not created, wrong result of proof-of-work")
                                self.mylogger.log(INFO, "Bid was not created")
                                self.exit(1)
        except:
            #print("Bid was not created")
            self.mylogger.log(INFO, "Bid was not created")
            raise

    def display_bids(self):
        """
        Display the bids performed by the current user
        """
        try:
            self.mylogger.log(INFO, "Displaying bids of the current client")
            for bid in self.bids:
                print(bid + "\n")
        except:
            #print("Cannot list current client's bids")
            self.mylogger.log(INFO, "Cannot list bids of current client")
            raise

    def check_receipt(self):
        """
        Verify if the information stored on the repository server is the
        same as in the receipt previously received. The hash of the bid is
        calculated both with the receipt information and the information received.
        If the hash is equal, the information stored in the server is correct.
        """
        try:
            self.mylogger.log(INFO, "Checking Receipt ")
            file_exists = False
            serial = input("Auction:")
            hash = input("Bid: ")

            file = "auction_{}_bid_{}.txt".format(serial, hash)

            while not file_exists:
                current_path = os.getcwd()
                path = "{}/receipts/{}".format(current_path, file)

                my_file = Path(path)
                if my_file.is_file():
                    file_exists = True
                    with open(path) as f:
                        lines = f.readlines()
                        break
                else:
                    print("Nonexistent file")
                    serial = input("Auction:")
                    hash = input("Bid: ")
                    file = "auction_{}_bid_{}.txt".format(serial, hash)

            receipt_dict = literal_eval(lines[0])

            hash_str = receipt_dict['bid']['key'] + receipt_dict['bid']['cert'] + receipt_dict['bid']['serial'] +\
                       receipt_dict['bid']['hash_prev'] + receipt_dict['bid']['amount'] + receipt_dict['bid']['name'] +\
                       receipt_dict['bid']['id'] + receipt_dict['bid']['timestamp']

            digest = hashlib.md5(hash_str.encode()).hexdigest()

            msg = {'payload': {'command': 'check_receipt', 'id': self.id, 'serial': serial, 'hash': hash}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.valid_signature(self.repo_pubkey, payload, signature):

                if 'info' not in data['payload']:
                    data = data['payload']

                    bid = data['bid']

                    repo_info = bid['key'] + bid['cert'] + bid['serial'] + bid['hash_prev'] + \
                                bid['amount'] + bid['id'] + bid['timestamp']

                    digest_repo = hashlib.md5(repo_info.encode()).hexdigest()

                    print("Hash computed from receipt: " + digest)
                    print("Hash computed from repository information: " + digest_repo)

                    if digest == digest_repo:
                        print("\nThe receipt's information is identical to the information stored on the server")
                    else:
                        print("\nThe receipt's information is NOT identical to the information stored on the server")
                        self.exit(0)
                else:
                    print("info: " + data['payload']['info'])

        except:
            #print("Cannot check the receipt")
            self.mylogger.log(INFO, "Cannot check the receipt")
            raise

    def display_ids(self):
        """
        Display the IDs of the clients currently active in the system
        """
        try:
            self.mylogger.log(INFO, "Listing ids of active clients")
            msg = {'payload': {'command': 'list_ids', 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature

            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)
            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.valid_signature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("\nNo active clients at the moment")
                    else:
                        for id in data['payload']['ids']:
                            print("\n" + id + "\n")
        except:
            print("Can't list ids of active clients")
            self.mylogger.log(INFO, "Cannot list ids")
            raise

    def list_active_auctions(self):
        """
        List the currently active auctions on the repository server
        """
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

            if self.valid_signature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("\nNo active auctions at the moment")
                else:
                    print(data['payload'])
        except:
            #print("Can't list active auctions")
            self.mylogger.log(INFO, "Cannot list active auctions")
            raise

    def list_closed_auctions(self):
        """
        List the closed auctions on the repository server
        """
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

            if self.valid_signature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("\nNo closed auctions at the moment")
                else:
                    print(data['payload'])
        except:
            print("Cannot list closed auctions")
            self.mylogger.log(INFO, "Cannot list closed auctions ")
            raise

    def bids_auction(self):
        """
        List all bids of an auction, given its serial number
        """
        try:
            serial = input("Serial number of auction:")
            self.mylogger.log(INFO, "Listing bids of an auction {}".format(serial))

            msg = {'payload': {'command': 'bid_auction', 'serial': serial, 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.valid_signature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("Auction has no bids")
                else:
                    print("\nBids of auction {}:".format(serial))
                    for key in data['payload'].keys():
                        print(data['payload'][key] + "\n")
        except:
            #print("Cannot list bids of an auction")
            self.mylogger.log(INFO, "Cannot list bids of an auction")
            raise

    def bids_client(self):
        """
        List all bids of a client, given his/her ID
        """
        try:
            id = input("Id of the client:")
            self.mylogger.log(INFO, "Listing bids of client {}".format(id))

            msg = {'payload': {'command': 'bid_client', 'c_id': id, 'id': self.id}}
            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature
            bytes = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            data, server = self.sock.recvfrom(MAX_BUFFER_SIZE)
            data = json.loads(data)

            signature = base64.b64decode(data['signature'])
            payload = json.dumps(data['payload'])

            if self.valid_signature(self.repo_pubkey, payload, signature):
                if 'ack' in data['payload']:
                    if data['payload']['ack'] == 'nok':
                        print("Client has no bids")
                else:
                    print("\nBids of client {}:".format(id))
                    for key in data['payload'].keys():
                        print(data['payload'][key] + "\n")

        except:
            #print("Cannot show bids of auction")
            self.mylogger.log(INFO, "Cannot show bids of auction")
            raise

    def display_client(self):
        """
        Display client's information (ID and name)
        """
        try:
            self.mylogger.log(INFO, "Displaying client's information")
            print("Name: {}, Id: {}".format(self.name, self.id))
        except:
            print("Cannot display client's information")
            self.mylogger.log(INFO, "Cannot display client's information")
            raise

    def hash_cash(self, r_string, numZeros):
        """
        Proof of work function that receives a random string from the repository
        and a number of zeros.
        First, a random string with 50 characters is computed. This string will then be
        joined with the string of the repository and a counter. The function will
        compute successive digests (SHA256) of that string and when the digest
        starts with numZeros 0's, the result was found.
        """
        try:
            self.mylogger.log(INFO, "Calculating proof-of-work: digest with {} zeros".format(numZeros))
            print("\n...calculating hash using hash-cash system")

            loop = True
            ctr = 0

            rand = base64.b64encode(
                ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50)).encode())

            while (loop):
                ctr += 1

                solution = False

                _string = r_string + ":" + rand.decode() + ":" + str(ctr)
                hash_object = hashlib.sha256(_string.encode('utf-8'))
                digest = hash_object.hexdigest()

                for i in range(0, int(numZeros)):
                    if digest[i] == "0":
                        solution = True
                    else:
                        solution = False
                        break

                if solution:
                    loop = False

            return _string, digest
        except:
            self.mylogger.log(INFO, "Exception on hash cash")
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
            self.mylogger.log(INFO, "Cannot validate signature")
            raise

    def exit(self, type):
        """
        Shutdown the client
        """
        try:
            self.mylogger.log(INFO, "Exiting client")
            msg = {'payload': {'exit': 'client exit', 'id': self.id}}

            signature = base64.b64encode(self.cc.sign_data(self.slot, json.dumps(msg['payload']))).decode()
            msg['signature'] = signature

            sent = self.sock.sendto(json.dumps(msg).encode(), self.man_address)
            sent = self.sock.sendto(json.dumps(msg).encode(), self.repo_address)

            self.mylogger.log(INFO, "Exiting Client")
            print("Exiting...")
            self.sock.close()
            sys.exit(type)
        except:
            self.mylogger.log(INFO, "Cannot exit client")
            raise


if __name__ == "__main__":

    c = Client(HOST, PORT_MAN, PORT_REPO)

    try:
        c.start()
    except KeyboardInterrupt:
        c.exit('0')