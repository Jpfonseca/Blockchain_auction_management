# Blockchain-based auction management

## About the project
Develop a system enabling users to create and participate in auctions. The system is composed by an auction manager, an auction repository and client applications. 
The system should be designed to support the following security features:
- Bids's confidentiality, integrity and authentication: Bids may contain secret material which can only be disclosed in special occasions,cannot be modified once accepted and cannot be forged on someone else's behalf;
- Bid acceptance control and confirmation: bids can only be accepted if fulfilling special criteria (in terms of structure), a source quenching mechanism must be used to reduce the amount of submitted bids, and accepted bids are unequivocally confirmed as such;
- Bid author identity and anonymity: Bids should be linked to subjects using their Portuguese Citizen Card. However, submitted
bids should remain anonymous until the end of the auction. 
- Honesty assurance: The auction repository must provide public access to all auctions and their bids, either finished or still active, and provide evidences of its honesty on each answer to a client request.
Furthermore, the auction repository cannot have access to any kind of information that may enable it to act differently to different clients.

##Files of the project

repo.py -> The repository server. Communicates with the client and the manager server.
man.py -> The manager server
valid.py -> The entity that validates a Bid. The validation code is sent by the client and the bid comes from the manager. The validation entity then sends the result to the manager.
client.py -> The client interface. Communicates only with the server repository
auction.py -> Structure of an auction. It contains a blockchain, a short name, a serial number (unique), a time limit for accepting new bids and a description.
security.py -> Entity that has all security functions, including some to access the citizen card.
blockchain.py -> Structure of the blockchain used in each auction. It is implemented as a linked list and each node (block) has the information of a bid.