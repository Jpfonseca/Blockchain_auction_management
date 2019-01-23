import json
import os
import re
from ast import literal_eval

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface


class Block:

    def __init__(self, serial=None, hash=None, hash_prev=None, amount=None, name=None, id=None, timestamp=None):
        self.mylogger = LoggyLogglyMcface(name=Block.__name__)
        self.mylogger.log(INFO, "Entering Block interface")

        self.serial = serial
        self.hash = hash
        self.hash_prev = hash_prev
        self.amount = amount
        self.name = name
        self.id = id
        self.timestamp = timestamp
        self.next = None
        self.previous = None

        self.block_dict = {'serial': serial, 'hash': hash, 'hash_prev': hash_prev, 'amount': amount, 'name': name, 'id': id,
                           'timestamp': timestamp}

    # get info about a bid
    def info(self):
        return str(self.block_dict)


class Blockchain:

    def __init__(self, serial=None, timestamp=None, name=None, time_limit=None, description=None, type=None, bidders=None,
                 limit_bids=None, state=None, winner=None, winner_amount=None):

        self.mylogger = LoggyLogglyMcface(name=Blockchain.__name__)
        self.mylogger.log(INFO, "Entering Blockchain interface")

        self.head_block = None
        self.tail_block = None
        self.serial = serial
        self.timestamp = timestamp
        self.name = name
        self.time_limit = time_limit
        self.description = description
        self.type = type
        self.bidders = bidders
        self.limit_bids = limit_bids
        self.state = state
        self.winner = winner
        self.winner_amount = winner_amount

        self.blockchain_dict = {'serial': serial, 'timestamp': timestamp, 'name': name, 'time-limit': time_limit,
                                'description': description, 'type': type, 'bidders': bidders, 'limit_bids': limit_bids,
                                'state': state, 'winner': winner, 'winner_amount': winner_amount}

    # get info about an auction
    def info(self):
        self.mylogger.log(INFO, "The Blockchain with the serial {} current state is :\n {}".format(self.serial, str(
            self.blockchain_dict)))
        return str(self.blockchain_dict)

    # return the number of blocks in the blockchain
    def chain_length(self):
        counter = 0
        current_block = self.head_block

        while current_block is not None:
            counter = counter + 1
            current_block = current_block.next
        self.mylogger.log(INFO, "The Blockchain with the serial {} has : {} blocks".format(self.serial, counter))
        return counter

    # get all bids of an identity
    def bids_client(self, id):
        result = []
        current_block = self.head_block
        self.mylogger.log(INFO, "The client with the id {} has these Bids:".format(id))

        while current_block is not None:
            if current_block.id == str(id) or current_block.id == int(id):
                result.append(current_block.info())
            current_block = current_block.next

        return result

    # get all bids of an auction
    def bids_auction(self, serial):
        result = []
        current_block = self.head_block
        self.mylogger.log(INFO,"The Blockchain with the serial {} has these Bids:".format(serial))

        while current_block is not None:
            if current_block.serial == str(serial) or current_block.serial == int(serial):
                result.append(current_block.info())
            current_block = current_block.next

        return result

    # write the current blockchain to a file
    def save_to_file(self, file):
        self.mylogger.log(INFO,"\nThe Blockchain will be saved into the file: {}\n".format(file))

        current_path = os.getcwd()
        path = "{}/auctions/{}".format(current_path, file)
        text_file = open(path, "w")
        text_file.write("%s\n" % self.info())

        current_block = self.head_block
        if current_block is not None:
            while current_block is not None:
                text_file.write("%s\n" % current_block.info())
                current_block = current_block.next

        text_file.close()
        self.mylogger.log(INFO, "The Blockchain was saved into the file: {}\n".format(file))

    # add block at the end of the blockchain
    def add_block(self, block):
        self.mylogger.log(INFO,
                          "Adding block into the blockchain: \n Hash: {}, Amount: {}, Identity: {}, Timestamp: {}"
                          "".format(block.hash, block.amount, block.id, block.timestamp))
        if isinstance(block, Block):
            if self.head_block is None:
                self.head_block = block
                block.previous = None
                block.next = None
                self.tail_block = block
            else:
                self.tail_block.next = block
                block.previous = self.tail_block
                self.tail_block = block
        return

    # remove all blocks in the blockchain
    def remove_blocks(self):
        counter = self.chain_length()
        self.mylogger.log(INFO,
                          "Removing all blocks from the Blockchain: {:d} blocks inside \n".format(counter))
        while counter > 0:
            current_block = self.tail_block
            self.tail_block = current_block.previous
            current_block.next = None
            current_block = None
            counter -= 1
        if counter == 0:
            self.head_block = None
            self.mylogger.log(INFO,
                              "Removed all blocks from the Blockchain\n")
        return