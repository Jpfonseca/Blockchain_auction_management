import hashlib
import json
import random
import string
from socket import *
import sys
import hashlib
from datetime import datetime

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface

HOST = "127.0.0.1"
# port client uses to communicate with client
PORT_MAN = 8080
PORT_REPO = 8081


class Client:
    def __init__(self, host, port_man, port_repo, client_pubkey, digest):

        self.mylogger = LoggyLogglyMcface(name=Client.__name__)
        self.mylogger.log(INFO, "Entering Client interface")

        self.host = host
        self.port_man = port_man
        self.port_repo = port_repo
        # public keys
        self.client_pubkey = json.dumps({'c_pubk': 'def', 'id': 1})
        self.man_pubkey = None
        self.repo_pubkey = None
        # id of the client
        self.digest = digest
        # addresses of the servers
        self.repo_address = None
        self.man_address = None
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        # active auctions
        self.active_auctions = []

    # Servers and Client exchange Public Keys
    def start(self):

        self.mylogger.log(INFO, "Exchanging public Key with the Repo")
        # send and receive public key (repository)
        bytes = self.sock.sendto(str.encode(self.client_pubkey), (self.host, self.port_repo))
        data1, address = self.sock.recvfrom(4096)
        print("> repository pubkey received")
        self.mylogger.log(INFO, "Repo Pubkey received")

        self.mylogger.log(INFO, "Exchanging public Key with the Manager")
        # send and receive public key (manager)
        bytes = self.sock.sendto(str.encode(self.client_pubkey), (self.host, self.port_man))
        data2, server = self.sock.recvfrom(4096)
        print("> manager pubkey received")
        self.mylogger.log(INFO, "Repo Pubkey received")

        self.mylogger.log(INFO, "Repo Pubkey : \n{:s}\nManager Pubkey : \n{:s}".format(data1['repo_pubk'],data2['man_pubk']))

        data1 = json.loads(data1)
        if 'repo_pubk' in data1:
            self.repo_pubkey = data1['repo_pubk']
            self.repo_address = address
        data2 = json.loads(data2)
        if 'man_pubk' in data2:
            self.man_pubkey = data2['man_pubk']
            self.man_address = server

        self.loop()

    # menu of the client
    def loop(self):
        self.mylogger.log(INFO, "Entered Client Menu")
        while (True):
            print("\n----Menu----\n1 - Create auction\n2 - Place bid\n3 - Check receipt\n4 - List active auctions\n"
                  "5 - List closed auctions\n6 - Close\n")

            option = input(">")

            if option == '1':
                self.create_auction()
            elif option == '2':
                self.place_bid()
            elif option == '3':
                self.check_receipt()
            elif option == '4':
                self.list_auctions()
            elif option == '5':
                self.list_closed_auctions()
            elif option == '6':
                sys.exit()
            else:
                print("Not a valid option!\n")

    # send new auction parameters to manager server
    def create_auction(self):
        self.mylogger.log(INFO, "Creating auction")
        try:
            name = input("Name: ")
            time_limit = input("Time limit: ")
            description = input("Description: ")
            type_auction = input("Type of auction (e/s):")
            bidders = input("Bidders ids:")
            limit_bids = input("Limit of bids:")

            if bidders and not limit_bids:
                msg = json.dumps({'auction': {'serial': None, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction, 'bidders': bidders}})
            elif limit_bids and not bidders:
                msg = json.dumps({'auction': {'serial': None, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction,
                                              'limit_bids': limit_bids}})
            elif bidders and limit_bids:
                msg = json.dumps({'auction': {'serial': None, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction, 'bidders': bidders,
                                              'limit_bids': limit_bids}})
            else:
                msg = json.dumps({'auction': {'serial': None, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction}})

            bytes = self.sock.sendto(str.encode(msg), (self.host, self.port_man))
            data, server = self.sock.recvfrom(4096)
            data = json.loads(data)
            print("This is the data\n")

            if data['ack'] == 'ok':
                print("New auction created!")
            else:
                print("The auction was NOT created")
        except:
            raise Exception("Cannot contact the manager")

    # request a bid, calculate proof-of-work, send parameters + answer to repository server
    def place_bid(self):
        self.mylogger.log(INFO, "Placing bid ")
        serial = input("Serial number of auction:")
        amount = input("Amount: ")

        # request bid creation and wait for proof-of-work
        msg = json.dumps({'command': 'bid_request', 'serial': serial})
        bytes = self.sock.sendto(str.encode(msg), self.repo_address)
        data, server = self.sock.recvfrom(4096)

        data = json.loads(data)
        answer = self.get_pow(data['size'])

        if data['type'] == 'e':
            date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            # encrypt identity
            print("Encrypted identity")
        else:
            date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            msg = json.dumps(
                {'bid': {'serial': serial, 'hash': answer, 'amount': amount, 'identity': self.digest,
                         'timestamp': date_time}})

        bytes = self.sock.sendto(str.encode(msg), self.repo_address)
        data, server = self.sock.recvfrom(4096)

        data = json.loads(data)

        if data['ack'] == 'ok':
            print("Bid created successfully")
        else:
            print("Bid not created")

    # verify if the receipt corresponds to the information retrieved from the repository
    def check_receipt(self):
        self.mylogger.log(INFO, "Checking Receipt ")
        msg = json.dumps({'command': 'check_receipt'})
        bytes = self.sock.sendto(str.encode(msg), self.repo_address)
        data, server = self.sock.recvfrom(4096)

    # list active auctions
    def list_auctions(self):
        try:
            self.mylogger.log(INFO, "List active auctions ")
            msg = json.dumps({'command': 'list_open'})
            bytes = self.sock.sendto(str.encode(msg), self.repo_address)
            data, server = self.sock.recvfrom(4096)
            data = json.loads(data)
            print(data)
        except:
            print("Can't list active auctions")
            self.mylogger.log(INFO, "Can't list active auctions")


    # list closed auctions
    def list_closed_auctions(self):
        try:
            self.mylogger.log(INFO, "List closed auctions ")
            msg = json.dumps({'command': 'list_closed'})
            bytes = self.sock.sendto(str.encode(msg), self.repo_address)
            data, server = self.sock.recvfrom(4096)
            data = json.loads(data)

            if data is not "":
                print(data)
            else:
                print("No closed auctions")
        except:
            print("Can't list closed auctions!")

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

        print("...calculating proof-of-work with size {}".format(size))

        while result is False:
            solution = self.gen_string(int(size))
            # hash = hashlib.sha256()
            # hash.update(answer)
            # solution = hash.hexdigest()

            if solution.startswith("111"):
                print("Answer: {}".format(solution))
                result = True

        return solution

    # See result of auction and close connection
    def close(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


if __name__ == "__main__":

    # get public key from CC
    publickey = "1234567890"

    # digest public key
    digest = hashlib.sha256(publickey.encode('utf-8')).hexdigest()

    c = Client(HOST, PORT_MAN, PORT_REPO, publickey, digest)

    try:
        c.start()
    except KeyboardInterrupt:
        print("Exiting...")
        c.close()
