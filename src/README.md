## Information on the src files and folders

### Files

- **blockchain.py**
The code for the creation of a linked list, with add, remove, save to file and load from file functions.

- **cc_interface.py**
All functions needed for interaction with the Citizen Card and associated security mechanisms.

- **client.py**
The client of our auction system. It has a simple user interface that allows the user to interact with all the functionalities of the system. Implements security mechanisms to communicate with the repository and manager servers.

- **log.py**
Logger of the system. The log messages of the project are written to a log.txt file (or to standard output).

- **man.py**
Is the manager server of the auction system. Receives auction requests and performs bid validations. It is also the server that computes the winner of an auction and decrypts the previously encrypted fields of the bid.

- **repo.py**
Is the repository of the auction system. Stores auctions and bids, both internally and in files. Cannot access encrypted fields of the bids and will only have access to that information at the end of the auction.

- **security.py**
Contains all the needed security functions, for encryption/decryption of information, signing and generating private/public keys.

- **validator.py**

The script that will execute the dynamic code uploaded by the client to the manager server, at the time of the auction creation.

### Folders

- **auctions**

Contains the .txt files of the auctions (both active and closed) and respective bids.

- **receipts**

Contains the .txt files of the receipts of the bids performed by clients.

- **certLists**

This folder holds the Certificate associated with the Root State Autority and the certificates for Authentication Certification chain under the it, needed to authenticate a Portuguese Citizen.

- **crlLists**

This folder holds the Certification Revogation Lists associated with the Authentication Certification Authority of the Portuguese Citizen Card

- **dynamicCode**

Contains the file with the dynamic code to be uploaded by the client upon the creation of the auction.
