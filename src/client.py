import json, random, string, sys, base64, datetime
from socket import *

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface
from cc_interface import PortugueseCitizenCard

HOST = "127.0.0.1"
# port client uses to communicate with client
PORT_MAN = 8080
PORT_REPO = 8081


class Client:
    def __init__(self, host, port_man, port_repo):

        self.mylogger = LoggyLogglyMcface(name=Client.__name__)
        self.mylogger.log(INFO, "Entering Client interface")

        self.host = host
        self.port_man = port_man
        self.port_repo = port_repo
        # public keys
        self.client_cert = None
        self.man_pubkey = None
        self.repo_pubkey = None
        # id (and name of the client
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

        # get cc certificate - cert (bytes)
        cert = self.cc.PTEID_GetCertificate(self.slot)
        self.client_cert=cert

        pubk = base64.b64encode(self.client_cert).decode()
        self.id = self.cc.certGetSerial()
        msg = json.dumps({'c_pubk': pubk, 'id': self.id})

        self.mylogger.log(INFO, "Exchanging certificate/pubkey with the Repo")
        bytes = self.sock.sendto(str.encode(msg), (self.host, self.port_repo))
        data1, address = self.sock.recvfrom(4096)
        print("> repository pubkey received")
        self.mylogger.log(INFO, "Repo Pubkey received")

        self.mylogger.log(INFO, "Exchanging certificate/pubkey with the Manager")
        bytes = self.sock.sendto(str.encode(msg), (self.host, self.port_man))
        data2, server = self.sock.recvfrom(4096)
        print("> manager pubkey received")
        self.mylogger.log(INFO, "Manager Pubkey received")

        data1 = json.loads(data1)
        data2 = json.loads(data2)

        self.repo_pubkey = base64.b64decode(data1['repo_pubk']).decode()
        self.man_pubkey = base64.b64decode(data2['man_pubk']).decode()

        if 'err' in data1:
            print("Invalid Certificate")
            sys.exit(-1)

        if 'repo_pubk' in data1:
            self.repo_address = address
        if 'man_pubk' in data2:
            self.man_address = server
        self.mylogger.log(INFO,
                          "Repo Pubkey : \n{}\nManager Pubkey : \n{}".format(self.repo_pubkey, self.man_pubkey))

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
                self.list_auctions()
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
                msg = json.dumps({'exit': 'client exit'})
                sent = self.sock.sendto(str.encode(msg), self.man_address)
                sent = self.sock.sendto(str.encode(msg), self.repo_address)
                #remove files
                self.mylogger.log(INFO, "Exiting Client")

                sys.exit()
            else:
                print("Not a valid option!\n")

    # send new auction parameters to manager
    def create_auction(self):
        self.mylogger.log(INFO, "Creating auction")
        try:
            name = input("Name: ")
            time_limit = input("Time limit: ") #format: 0h0m30s
            description = input("Description: ")
            type_auction = input("Type of auction (e/s):")
            bidders = input("Bidders ids:")
            limit_bids = input("Limit of bids:")

            date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

            if bidders and not limit_bids:
                msg = json.dumps({'auction': {'serial': None, 'timestamp': date_time, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction, 'bidders': bidders},
                                  'signature': 'oi'})
            elif limit_bids and not bidders:
                msg = json.dumps({'auction': {'serial': None, 'timestamp': date_time, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction,
                                              'limit_bids': limit_bids},
                                  'signature': 'oi'})
            elif bidders and limit_bids:
                msg = json.dumps({'auction': {'serial': None, 'timestamp': date_time, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction, 'bidders': bidders,
                                              'limit_bids': limit_bids},
                                  'signature': 'oi'})
            else:
                msg = json.dumps({'auction': {'serial': None, 'timestamp': date_time, 'name': name, 'time-limit': time_limit,
                                              'description': description, 'type': type_auction},
                                  'signature': 'oi'})

            bytes = self.sock.sendto(str.encode(msg), (self.host, self.port_man))
            data, server = self.sock.recvfrom(4096)
            data = json.loads(data)

            if data['ack'] == 'ok':
                print("\nNew auction created!")
                print(data['info'])
            else:
                print("The auction was NOT created")
        except:
            raise Exception("Cannot contact the manager")

    # request a bid, calculate proof-of-work, send parameters to repository
    def place_bid(self):
        self.mylogger.log(INFO, "Placing bid ")
        serial = input("Serial number of auction:")
        amount = input("Amount: ")

        # request bid creation and wait for proof-of-work parameter
        msg = json.dumps({'command': 'bid_request', 'serial': serial, 'signature': 'oi'})
        bytes = self.sock.sendto(str.encode(msg), self.repo_address)
        data, server = self.sock.recvfrom(4096)
        data = json.loads(data)
        answer = self.get_pow(data['size'])

        if data['type'] == 'e':
            date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            # encrypt name
            msg = json.dumps({'bid': {'serial': serial, 'hash': answer, 'amount': amount, 'name': self.name,
                                      'identity': self.id,'timestamp': date_time}, 'signature': 'oi'})
        else:
            date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            msg = json.dumps({'bid': {'serial': serial, 'hash': answer, 'amount': amount, 'name': self.name,
                                      'identity': self.id, 'timestamp': date_time}, 'signature': 'oi'})

        bytes = self.sock.sendto(str.encode(msg), self.repo_address)
        data, server = self.sock.recvfrom(4096)

        data = json.loads(data)

        if data['ack'] == 'ok' and 'info' in data:
            print("\nBid created successfully")
            print(data['info'])
        else:
            print("\nBid not created - auction serial does not exist")

    # verify if the receipt corresponds to the information retrieved from the repository
    def check_receipt(self):
        self.mylogger.log(INFO, "Checking Receipt ")
        msg = json.dumps({'command': 'check_receipt', 'signature': 'oi'})
        bytes = self.sock.sendto(str.encode(msg), self.repo_address)
        data, server = self.sock.recvfrom(4096)

    # list active auctions
    def list_auctions(self):
        try:
            self.mylogger.log(INFO, "List active auctions ")
            msg = json.dumps({'command': 'list_open', 'signature': 'oi'})
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
            msg = json.dumps({'command': 'list_closed', 'signature': 'oi'})
            bytes = self.sock.sendto(str.encode(msg), self.repo_address)
            data, server = self.sock.recvfrom(4096)
            data = json.loads(data)

            if data is not "":
                print(data)
            else:
                print("No closed auctions")
        except:
            print("Can't list closed auctions!")

    # list all bids of an auction
    def bids_auction(self):
        serial = input("Serial number of auction:")

        msg = json.dumps({'command': 'bid_auction', 'serial': serial, 'signature': 'oi'})

        bytes = self.sock.sendto(str.encode(msg), self.repo_address)

        data, server = self.sock.recvfrom(4096)
        data = json.loads(data)

        print("\nBids of auction {}:".format(serial))

        if data is not "":
            for bid in data.keys():
                if bid != 'signature':
                    print(data[bid])
        else:
            print("Auction has no bids")

    # list all bids of a client
    def bids_client(self):
        try:
            id = input("Id of the client:")

            if id == self.id:
                msg = json.dumps({'command': 'bid_client', 'id': id, 'signature': 'oi'})
                bytes = self.sock.sendto(str.encode(msg), self.repo_address)
                data, server = self.sock.recvfrom(4096)
                data = json.loads(data)

                print("\nBids of client {}:".format(id))

                if data is not "":
                    for bid in data.keys():
                        if bid != 'signature':
                            print(data[bid] + "\n")

            else:
                msg = json.dumps({'command': 'bid_client', 'id': id, 'signature': 'oi'})
                bytes = self.sock.sendto(str.encode(msg), self.repo_address)
                data, server = self.sock.recvfrom(4096)
                data = json.loads(data)

                print("\nBids of client {}:\n".format(id))

                if data is not "":
                    for bid in data.keys():
                        if bid != 'signature':
                            print(data[bid] + "\n")
        except:
            print("Cannot show bids of auction")


    def validate_receipt(self):
        print("Validating receipt")
    #def validate_receipt()

    def display_client(self):
        print("Name: {}, Id: {}".format(self.name,self.id))

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

            if solution.startswith("111"):
                print("Answer: {}".format(solution))
                result = True

        return solution

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
        sent = c.sock.sendto(str.encode(msg), c.man_address)
        sent = c.sock.sendto(str.encode(msg), c.repo_address)
        self.mylogger.log(INFO, "Exiting Client")
        print("Exiting...")
        c.close()
