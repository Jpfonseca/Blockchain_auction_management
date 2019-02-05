## About the project

Develop a system enabling users to create and participate in auctions. The system is composed by an auction manager, an auction repository and client applications. 
The system should be designed to support the following security features:

- Bids's confidentiality, integrity and authentication: Bids may contain secret material which can only be disclosed in special occasions,cannot be modified once accepted and cannot be forged on someone else's behalf;
- Bid acceptance control and confirmation: bids can only be accepted if fulfilling special criteria (in terms of structure), a source quenching mechanism must be used to reduce the amount of submitted bids, and accepted bids are unequivocally confirmed as such;
- Bid author identity and anonymity: Bids should be linked to subjects using their Portuguese Citizen Card. However, submitted
bids should remain anonymous until the end of the auction. 
- Honesty assurance: The auction repository must provide public access to all auctions and their bids, either finished or still active, and provide evidences of its honesty on each answer to a client request.
Furthermore, the auction repository cannot have access to any kind of information that may enable it to act differently to different clients.

## Information on the src files and folders

### Files

- **blockchain.py**:
The code for the creation of a linked list, with add, remove, save to file and load from file functions.

- **cc_interface.py**:
All functions needed for interaction with the Citizen Card and associated security mechanisms.

- **client.py**:
The client of our auction system. It has a simple user interface that allows the user to interact with all the functionalities of the system. Implements security mechanisms to communicate with the repository and manager servers.

- **log.py**:
Logger of the system. The log messages of the project are written to a log.txt file (or to standard output).

- **man.py**:
Is the manager server of the auction system. Receives auction requests and performs bid validations. It is also the server that computes the winner of an auction and decrypts the previously encrypted fields of the bid.

- **repo.py**:
Is the repository of the auction system. Stores auctions and bids, both internally and in files. Cannot access encrypted fields of the bids and will only have access to that information at the end of the auction.

- **security.py**:
Contains all the needed security functions, for encryption/decryption of information, signing and generating private/public keys.

- **validator.py**:
The script that will execute the dynamic code uploaded by the client to the manager server, at the time of the auction creation.

- **grabcrls.sh**
The script that should be run to fetch the most recent Certificate revocation lists associated with the Citizen Card Certificates. The CRL's are updated each week(Sundays) by the Portuguese authorities.

### Folders

- **auctions**:
Contains the .txt files of the auctions (both active and closed) and respective bids.

- **receipts**:
Contains the .txt files of the receipts of the bids performed by clients.

- **certLists**:
This folder holds the Certificate associated with the Root State Autority and the certificates for Authentication Certification chain under the it, needed to authenticate a Portuguese Citizen.

- **crlLists**:
This folder holds the Certification Revogation Lists associated with the Authentication Certification Authority of the Portuguese Citizen Card

- **dynamicCode**:
Contains the file with the dynamic code to be uploaded by the client upon the creation of the auction.

# Deploying the project

The project must be executed using Python 3.


If you're running Ubuntu, you will need to install Swig:

`sudo apt-get install swig`

It is advised to run the project inside a python virtual environment, which can be installed and activated as follows.
The commands should be executed inside the root folder of the project:

`python3 -m pip install --user virtualenv`

`python3 -m  virtualenv venv`

`source venv/bin/activate`

The virtual environment is now currently activated.  Next, you will need to run the following command for installation of the required packages:

`pip3 install -r requirements.txt`

Finally,  the  project  must  be  run  in  the  following  sequence on different terminal tabs/windows(repo.py,  then  man.py,  then
client.py):

- TAB 1: `cd src/` && `python3 repo.py`

- TAB 2: `cd src/` && `python3 man.py`

- TAB 3: `cd src/` && `python3 client.py`
