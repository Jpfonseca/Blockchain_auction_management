import base64
import json
import sys
from socket import *
from blockchain import *
from ast import literal_eval

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface
from security import GenerateCertificates, CryptoUtils

from cryptography.fernet import Fernet
from cc_interface import PortugueseCitizenCard


HOST = "127.0.0.1"
PORT = 8080
PORT_REPO = 8081

class Manager:
    def __init__(self, host, port):
        self.mylogger = LoggyLogglyMcface(name=Manager.__name__)
        self.mylogger.log(INFO, "Entering Manager interface")

        self.name = Manager.__name__
        self.privKname = "privK" + self.name

        self.password = "1234"
        self.privateKey = None
        self.man_pubkey = None
        self.man_pubkeyb = None

        self.loggedInClient = 0

        self.host = host
        self.port = port
        # stored public keys
        self.repo_pubkey = None
        self.pubkey_dict = {}
        # list of addresses
        self.address_client = []
        self.repo_address = None
        # list of active and closed auctions
        self.active_auctions = []
        self.closed_auctions = []
        # socket to be used
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # current client being served
        self.current_client = None
        # generate public and private key
        self.certgen = GenerateCertificates()
        self.crypto = CryptoUtils()
        self.cc = PortugueseCitizenCard()

    # server and client exchange public keys
    def start(self):
        # verify if manager private key already exists. load if true
        if self.certgen.checkExistence(self.name):
            self.certgen.loadPrivateKeyFromFile(self.privKname, password=self.password)
        else:
            self.certgen.writePrivateKeyToFile(self.privKname, password=self.password)

        # get public key of manager and store to global variable
        self.man_pubkeyb = self.certgen.publicKeyToBytes()
        self.man_pubkey = base64.b64encode(self.man_pubkeyb).decode()

        print("Listening...")

        # 1) exchange public keys with the repository
        self.mylogger.log(INFO, "Exchanging public Key with the Repo")
        msg = json.dumps({'man_pubk': self.man_pubkey})
        sent = self.sock.sendto(str.encode(msg), (self.host, PORT_REPO))
        print("> repository pubkey received")
        data1, self.repo_address = self.sock.recvfrom(4096)
        self.mylogger.log(INFO, "Repo Pubkey received")

        # store the received repository public key in global variable
        data1 = json.loads(data1)
        if 'repo_pubk' in data1:
            self.repo_pubkey = base64.b64decode(data1['repo_pubk'].encode())
        self.mylogger.log(INFO, "Repo Pubkey : \n{}".format(self.repo_pubkey))

        # 2) exchange public key with client
        self.mylogger.log(INFO, "Exchanging public Key with the Client")
        data2, client_addr = self.sock.recvfrom(4096)
        print("> client pubkey received")
        sent = self.sock.sendto(str.encode(msg), client_addr)
        self.mylogger.log(INFO, "Client Pubkey received")

        data2 = json.loads(data2)
        self.clientLogin(data2, client_addr)

        self.loop()

        # manager waits for client or repository messages
    def loop(self):
        while (True):
            data, addr = self.sock.recvfrom(4096)
            data2 = json.loads(data)

            # add new client
            if (addr not in self.address_client) and (addr != self.repo_address):
                print("> client pubkey received")
                msg = json.dumps({'man_pubk': self.man_pubkey})
                sent = self.sock.sendto(str.encode(msg), addr)
                self.clientLogin(data2, addr)
                self.loggedInClient += 1

            if 'auction' in data2:
                self.createAuction(data2, addr)

            if 'ack' in data2:
                if data2['ack'] == 'ok':
                    if data2['info'] == 'auction':
                        print("> auction creation: OK")
                    if data2['info'] == 'bid':
                        print("> bid creation: OK")
                    data2['signature'] = 'oi'
                    data = json.dumps(data2)
                    sent = self.sock.sendto(str.encode(data), self.current_client)

                elif data2['ack'] == 'nok':
                    if data2['info'] == 'auction':
                        print("> auction creation: NOT OK")
                    if data2['info'] == 'bid':
                        print("> bid creation: NOK")
                    data2['signature'] = 'oi'
                    data = json.dumps(data2)
                    sent = self.sock.sendto(str.encode(data), self.current_client)

            if 'end' in data2:
                winner_dict = {}
                result = []

                print("> auction ended")

                # load the auction file and calculate the winner
                with open(data2['end']) as f:
                    lines = f.readlines()

                auction = lines.pop(0)
                auction_dict = literal_eval(auction)

                for line in lines:
                    line = line[:-1]
                    bid = literal_eval(line)
                    winner_dict[str(bid['id'])] = bid['amount']

                    # decrypt bids

                winner = max(zip(winner_dict.values(), winner_dict.keys()))

                auction_dict['winner'] = winner[1]
                auction_dict['winner_amount'] = winner[0]
                auction_dict['state'] = 'closed'

                result.append(str(auction_dict))

                for line in lines:
                    line = line[:-1]
                    result.append(line)

                with open(data2['end'], 'w') as f:
                    for line in result:
                        f.write("%s\n" % line)

                # the winner was found and the new blockchain was written to the file
                msg = json.dumps({'ack': 'ok'})
                sent = self.sock.sendto(str.encode(msg), self.repo_address)
            if 'exit' in data2:
                self.loggedInClient -= 1
                if self.loggedInClient == 0:
                    self.mylogger.log(INFO, "Exiting Manager")
                    sys.exit(-1)

    #
    def createAuction(self, msg, addr):
        # {'payload':{'key':key,'cert',cert,'auction':{...}}, 'signature': signature}

        # extract auction parameters
        auction = msg['payload']['auction']

        # verify client's signature (msg['signature'])
        pubk = self.pubkey_dict[base64.b64decode(msg['id']).encode()]
        payload = json.dumps(msg['payload'])

        signature = base64.b64decode(msg['signature']).encode()

        # decrypt symmetric key msg['key'] with manager private key
        encryptedKey = base64.b64decode(msg['payload']['key']).encode()
        key = self.crypto.RSADecryptData(self, self.privateKey, encryptedKey)

        # decrypt client's certificate msg['cert']
        f = Fernet(key)
        encryptedCert = base64.b64decode(msg['payload']['cert']).encode()
        cert = f.decrypt(encryptedCert)
        self.certops.getCertfromPem(cert)
        cert_pubk = self.certops.getPubKey()
        # Pem
        message = {'ack': 'nok'}

        valid = True

        if not cert_pubk.decode() == pubk.decode():
            message['info'] = 'diff pubk'
            valid = False
            if not self.cc.verifyChainOfTrust(cert):
                message['info'] = 'cc cert not verified'
                valid = False
                if not self.crypto.verifySignature(pubk, payload, signature):
                    message['info'] = 'signature not verified'
                    valid = False

        if not valid:
            bytes = self.sock.sendto(str.encode(message), addr)
        else:
            print("> valid client's signature")
            self.mylogger.log(INFO, "Verified Client Payload :\n{}".format(payload))

            auction = msg['payload']['auction']
            msg = {'payload': {'auction': auction, 'valid': valid}}

            signature = base64.b64encode(self.certgen.signData(json.dumps(msg['payload']))).decode()

            msg['signature'] = signature

            bytes = self.sock.sendto(str.encode(json.dumps({'ack': 'ok'})), addr)

            # send: auction + validation of client's certificate + signature
            sent = self.sock.sendto(str.encode(msg), self.repo_address)
            self.current_client = addr

    # verify client's cert, store client's certificate in dictionary with 'id' keys
    def clientLogin(self, message, client_addr):
        cert = None
        if 'c_pubk' in message:
            pubk = base64.b64decode(message['c_pubk'].encode())

        self.mylogger.log(INFO, "Client Pubkey : \n{}".format(pubk))
        # cc = PortugueseCitizenCard()
        # verified = cc.verifyChainOfTrust(cert)

        # if not verified:
        #     self.mylogger.log(ERROR, "Invalid Client Certificate {}".format(cert))
        #     msg = json.dumps({'err': 'invalid certificate'})
        #     sent = self.sock.sendto(str.encode(msg), client_addr)
        #     if self.loggedInClient == 0:
        #         print("> invalid client certificate")
        #         sys.exit(-1)
        #
        # print("> client certificate verified ")
        # self.mylogger.log(INFO, "Verified Client Certificate {}".format(cert))
        self.loggedInClient += 1
        self.pubkey_dict[message['id']] = pubk
        self.address_client.append(client_addr)

if __name__ == "__main__":
    r = Manager(HOST, PORT)
    try:
        r.start()
    except KeyboardInterrupt:
        print("Exiting...")