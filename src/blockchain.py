class Block:
    def __init__(self, hash=None, amount=None, identity=None, timestamp=None):
        self.hash = hash
        self.amount = amount
        self.identity = identity
        self.timestamp = timestamp

        self.next = None
        self.previous = None


class Blockchain:
    def __init__(self, name=None, serial=None, time_limit=None, description=None, bidders=None, limit_bids=None):
        self.head_block = None
        self.tail_block = None

        self.name = name
        self.serial = serial
        self.time_limit = time_limit
        self.description = description
        self.bidders = bidders
        self.limit_bids = limit_bids

    # return the number of blocks in the blockchain
    def chain_length(self):
        counter = 0
        current_block = self.head_block

        while current_block is not None:
            counter = counter + 1
            current_block = current_block.next

        return counter

    #get info about an auction (blockchain)
    def info(self):
        print("Name: %s, Serial Number: %s, Time limit: %s, Description: %s, Bidders: %s, Limit of bids per bidder: %s" \
                                        %(self.name,self.serial,self.time_limit,self.description,self.bidders,self.limit_bids))

    # get all data of all bids
    def output_blockchain(self):
        current_block = self.head_block

        while current_block is not None:
            print("Hash: %s, Amount: %f, Identity: %s" % (
                current_block.hash, current_block.amount, current_block.identity))
            current_block = current_block.next
        return

    # get all bids of a certain identity
    def output_bids(self, identity):
        current_block = self.head_block

        while current_block is not None:
            if current_block.identity == identity:
                print("Hash: %s, Amount: %f, Identity: %s" % (
                    current_block.hash, current_block.amount, current_block.identity))
            current_block = current_block.next
        return

    # get bid of a certain identity, processed at a certain timestamp
    def output_bid(self, identity, timestamp):
        current_block = self.head_block

        while current_block is not None:
            if current_block.identity == identity and current_block.timestamp == timestamp:  # current_node.has_value(value)
                print("Hash: %s, Amount: %f, Identity: %s" % (current_block.hash, current_block.amount, current_block.identity))
            current_block = current_block.next
        return

    #write the current blockchain to file
    def chain_to_file(self, file):
        text_file = open(file, "w")
        current_block = self.head_block

        while current_block is not None:
            text_file.write("%s %f %s\n" % (current_block.hash, current_block.amount, current_block.identity))
            current_block = current_block.next

        text_file.close()

    #load a blockchain from a file
    def load_file(self, file):
        with open(file) as f:
            content = f.readlines()
        content = [x.strip("\n") for x in content]

        for line in content:
            hash, amount, identity = line.split()
            block_line = Block(hash, float(amount), identity)
            self.add_block(block_line)

        self.tail_block = block_line

    #add block at the end of the blockchain
    def add_block(self, block):
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

    #remove all blocks in the blockchain
    def remove_blocks(self):
        counter = self.chain_length()

        while counter > 0:
            current_block = self.tail_block
            self.tail_block = current_block.previous
            current_block.next = None
            current_block = None
            counter -= 1
        if counter == 0:
            self.head_block = None
        return



"""
#Testing

chain1 = Blockchain("auction1", "12345", "12-12-2019", "auction of shoes")
chain1.info()

chain1.add_block(Block("ahsdgetgatgsc", 300, "atsgwrefdy152", "1-12-2018 23:15"))
chain1.add_block(Block("ah333etgatgsc", 350, "atsgwrefdy153", "1-12-2018 23:20"))
chain1.add_block(Block("ahsdget222gsc", 400, "atsgwrefdy154", "1-12-2018 23:22"))

chain1.chain_length()

print("\n> Output of blockchain")
chain1.output_blockchain()
print("\n> Output of all bids of a user")
chain1.output_bids("atsgwrefdy153")
print("\n> Output of a bid of a user (defined timestamp)")
chain1.output_bid("atsgwrefdy152", "1-12-2018 23:15")

print("\n> Loading blockchain from file")
chain1.chain_to_file("chain_output.txt")
chain1.load_file("chain_output.txt")
chain1.output_blockchain()

print("\n> Removing blockchain from memory")
chain1.remove_blocks()
chain1.output_blockchain()
"""