# Blockchain-based auction management

## Objective
Develop a system enabling users to create and participate in auctions. The system is composed by an auction manager, an auction repository and client applications. The system should be designed to support the following security features:
- Bids's confidentiality, integrity and authentication: Bids may contain secret material which can only be disclosed in special occasions,cannot be modified once accepted and cannot be forged on someone else's behalf;
- Bid acceptance control and confirmation: bids can only be accepted if fulfilling special criteria (in terms of structure), a source quenching mechanism must be used to reduce the amount of submitted bids, and accepted bids are unequivocally confirmed as such;
- Bid author identity and anonymity: Bids should be linked to subjects using their Portuguese Citizen Card. However, submitted
bids should remain anonymous until the end of the auction. 
- Honesty assurance: The auction repository must provide public access to all auctions and their bids, either finished or still active, and provide evidences of its honesty on each answer to a client request.
Furthermore, the auction repository cannot have access to any kind of information that may enable it to act differently to different clients.

