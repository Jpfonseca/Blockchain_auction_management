from os import listdir
from time import sleep
import PyKCS11
from PyKCS11 import PyKCS11Error, PyKCS11Lib, Mechanism

from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext,\
    X509StoreFlags, X509StoreContextError

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.exceptions import *

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface


class PortugueseCitizenCard:
    """
    This class specifies all operations that can be executed on a provided Portuguese Citizen Card connected to the
    computer, based on the slot they are occupying.
    The class depends on the libs :
        - cryptography: available @ github.com/pyca/cryptography
        - pyopenssl:available @ github.com/pyca/pyopenssl
        - PyKCS11 :available @ github.com/LudovicRousseau/PyKCS11
    """

    def __init__(self):
        """
        Initialization of the Class:
        - All certs/crls needed for the CC validation are loaded
        - All the Smartcards Names are retreived
        """
        self.mylogger = LoggyLogglyMcface(name=PortugueseCitizenCard.__name__)
        self.mylogger.log(INFO, "Entering CC interface")

        self.cert=None

        rootCerts, trustedCerts, crlList = self._loadPkiCertsAndCrls()
        self.mylogger.log(INFO, "Loaded all Certificates and CRL's")

        self.ccStoreContext = self._ccStoreContext(rootCerts, trustedCerts, crlList)
        self.mylogger.log(INFO,
                          "Store Context description completed")

        self.lib = "libpteidpkcs11.so"
        self.cipherMechanism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, "")
        self.sessions = self.__initPyKCS11__()
        self.fullnames = self.getSmartcardsNames()

    def _loadPkiCertsAndCrls(self):
        """
        Private method to convert all the data retrived from the cert and crl files encoded in PEM or ASN1 format
        :return:
        """
        rootCerts = ()
        trustedCerts = ()
        crlList = ()

        basename = ["certLists/", "crlLists/"]

        for filename in listdir(basename[0]):
            try:
                cert_info = open(basename[0] + filename, 'rb').read()
            except IOError:
                self.mylogger.log(ERROR, "IO Exception while reading file : {:s} {:s}".format(basename[0], filename))
                exit(10)
            else:
                if ".cer" in filename:
                    try:
                        if "0012" in filename or "0013" in filename:
                            certAuth = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            certAuth = load_certificate(FILETYPE_ASN1, cert_info)
                    except Error:
                        self.mylogger.log(ERROR, "Exception while loading certificate from file : {:s} {:s}".format(
                            basename[0], filename))
                        exit(10)
                    else:
                        trustedCerts = trustedCerts + (certAuth,)
                elif ".crt" in filename:
                    try:
                        if "ca_ecc" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        elif "-self" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            root = load_certificate(FILETYPE_ASN1, cert_info)
                    except Error:
                        self.mylogger.log(ERROR, "Exception while loading certificate from file : {:s} {:s}".format(
                            basename[0], filename))
                        exit(10)
                    else:
                        rootCerts = rootCerts + (root,)

        self.mylogger.log(INFO, "Loaded Root certificates : {:d} out of {:d} ".format(len(rootCerts),
                                                                                      len(listdir(basename[0]))))
        self.mylogger.log(INFO, "Loaded Authentication certificates: {:d} out of {:d} ".format(len(trustedCerts), len(
            listdir(basename[0]))))

        for filename in listdir(basename[1]):
            try:
                crl_info = open(basename[1] + "/" + filename, 'rb').read()
            except IOError:
                self.mylogger.log(ERROR, "IO Exception while reading file : {:s} {:s}".format(basename[0], filename))
            else:
                if ".crl" in filename:
                    crls = load_crl(FILETYPE_ASN1, crl_info)
            crlList = crlList + (crls,)
        self.mylogger.log(INFO, "Certificate revocation lists loaded: {:d} out of {:d} ".format(len(crlList), len(
            listdir(basename[1]))))

        return rootCerts, trustedCerts, crlList

    def _ccStoreContext(self, rootCerts, trustedCerts, crlList):
        """
        This method creates a X509StoreContext Description that can be used to validate a given Citizen Card
        :param rootCerts: X509 Certificates from the root entities of the Portuguese Citizen Card
        :param trustedCerts: X509 Authentication Certificates from the Portuguese Citizen Card Autority
        :param crlList: X509 Authentication Certificates Revocation Lists from the Portuguese Citizen Card Autority
        :return:
        """
        try:
            store = X509Store()

            i = 0
            for _rootCerts in rootCerts:
                store.add_cert(_rootCerts)
                i += 1

            self.mylogger.log(INFO, "Root Certificates Added to the X509 Store Context description : {:d}".format(i))

            i = 0
            for _trustedCerts in trustedCerts:
                store.add_cert(_trustedCerts)
                i += 1

            self.mylogger.log(INFO,
                              "Trusted Authentication Certificates Added to the X509 Store Context description : {:d}".format(
                                  i))

            i = 0
            for _crlList in crlList:
                store.add_crl(_crlList)
                i += 1

            self.mylogger.log(INFO,
                              "Certificates Revocation Lists Added to the X509 Store Context description : {:d}".format(
                                  i))

            store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
        except X509StoreContext:
            self.mylogger.log(ERROR, "Store Context description failed")
            return None
        else:
            return store

    def __initPyKCS11__(self):
        """
        This method will initialize the use of the the PyKCS11 module developed by Ludovic Rousseau which is available on https://pypi.org/project/pykcs11/
           and whose source code is available at https://github.com/LudovicRousseau
        :return: list of open sessions
        """

        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"
        AUTH_KEY_LABEL = "CITIZEN AUTHENTICATION KEY"

        SIGN_CERT_LABEL = "CITIZEN SIGNATURE CERTIFICATE"
        SIGN_KEY_LABEL = "CITIZEN SIGNATURE KEY"

        self.mylogger.log(INFO, "Entering PyKCS11 init ")
        try:
            pkcs11 = PyKCS11Lib()
            pkcs11.load(self.lib)
        except PyKCS11Error:
            self.mylogger.log(ERROR, "PortugueseCitizenCard:   We couldn't load the PyKCS11 lib")
            Exception("We couldn't load the lib")
            exit(10)
        except KeyboardInterrupt:
            self.mylogger.log(INFO, "PortugueseCitizenCard:   Exiting Module by Keyboard Interruption")
            exit(0)
        else:
            try:
                # listing all card slots
                self.slots = pkcs11.getSlotList(tokenPresent=True)
                self.mylogger.log(INFO, "The program found " + str(len(self.slots)) + " slots")

                if len(self.slots) < 1:
                    exit(-1)

                return [pkcs11.openSession(self.slots[x]) for x in range(0, len(self.slots))]

            except KeyboardInterrupt:
                self.mylogger.log(INFO, "Exiting Module by Keyboard Interruption")
                exit(0)
            except PyKCS11Error:
                self.mylogger.log(ERROR, "We couldn't execute the method openSession for the given smartcard")
                exit(10)
            except:
                self.mylogger.log(ERROR, "Exiting Module because no CC was found")
                exit(11)

    def PTEID_GetID(self, sessionIdx):
        """
        This method gets the Name of the owner of the CC by fetching it from the CKA_SUBJECT field on the present CC session

        :param sessionIdx: index of the slot with a openSession
        :return: fullname of the person or None if no fullname is found
        """
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

        self.mylogger.log(INFO, "Entering PTEID_GetID with PyKCSS session id: {:2d}".format(sessionIdx))

        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))
        except PyKCS11Error:
            self.mylogger.log(ERROR,
                              "The the smartcard with the id: {:3d} unexpectedly closed the session".format(
                                  sessionIdx))
            return None
        else:
            try:
                infos1 = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in info][0])
            except (IndexError, TypeError):
                self.mylogger.log(ERROR,
                                  " Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(
                                      AUTH_CERT_LABEL))
                return None
            else:
                names = infos1.split("BI")[1].split("\x0c")
                return ' '.join(names[i] for i in range(1, len(names)))

    def certGetSerial(self):
        """
        Method to return CC serial number
        :return: int
        """
        if not self.cert is None:

            return self.cert.serial
        return None

    def PTEID_GetCertificate(self, slot):
        """
        Method to retreive the CITIZEN AUTHENTICATION CERTIFICATE from a connected CC smartcard
        :param slot: slot number
        :return:- X509 Certificate if the certificate is found
                - None if no certificate is found
        """

        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

        self.mylogger.log(INFO, "Entering PTEID_GetCertificate with PyKCSS session id :{:2d}".format(slot))

        try:
            info = self.sessions[slot].findObjects(
                template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL, AUTH_CERT_LABEL)]))
        except PyKCS11Error:
            self.mylogger.log(ERROR,
                              "The the smartcard in the slot with the id: {:3d} unexpectedly closed the session".format(
                                  slot))
            exit(12)
        else:
            try:

                der = bytes([c.to_dict()['CKA_VALUE'] for c in info][0])

            except (IndexError, TypeError):
                self.mylogger.log(ERROR,
                                  " Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(
                                      AUTH_CERT_LABEL))
                return None
            else:
                # converting DER format to x509 certificate
                try:
                    cert = x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)
                except:
                    self.mylogger.log(ERROR,
                                      " Certificate for smartcard in the slot:{:2d} wasn't loaded: \n".format(slot))
                    return None
                else:
                    self.mylogger.log(INFO,
                                      " Certificate for smartcard in the slot:{:2d} loaded:\n {:s}".format(slot,
                                                                                                           cert.decode(
                                                                                                               "utf-8")))
                    self.cert = x509.load_pem_x509_certificate(cert, default_backend())
                    return cert

    def getSmartcardsNames(self):
        """
        This method gets all names of the owners of the Portuguese Citizen Cards attached to the Computer
        :return:- None : No citizen card found
                - fullnames :List of names of the cards of the slots available
        """
        try:
            fullnames = [self.PTEID_GetID(i) for i in self.slots]
        except:
            self.mylogger.log(ERROR,
                              "The service was unable to fetch all smartcards data")
            return None
        else:
            return fullnames

    def login(self, slot):
        """
        This method can be used to login a User into a PyKCS11 session of the Citizen Card
        :param slot: number of the slot in which the smartcart is connected to
        :return:-True : if the login is sucessfull
                -False : if the login is not sucessfull
        """
        session = self.sessions[slot]
        name = self.fullnames[slot]
        pin = None
        while True:
            pin = input("Please insert your authentication pin:")
            if isinstance(pin, str):
                if not len(pin) == 4:
                    print("Your Pin is invalid ! It should have 4 digits: %s \n" % pin)
                else:
                    if not pin.isdigit():
                        print("Your Pin is invalid ! It should have 4 digits: %s \n" % pin)
                    else:
                        try:
                            if name == self.getSmartcardsNames()[slot]:
                                session.login(pin)
                        except PyKCS11Error:
                            self.mylogger.log(ERROR, "Couldn't login into the card on slot {:d}".format(slot))
                            return False
                        else:
                            sleep(2)
                            self.mylogger.log(INFO, "Session Login Initiated for smartcard on slot {:d}".format(slot))
                            return True

    def verifyChainOfTrust(self, cert):
        """
        This method verifies if the given certificate is valid under the Authority of the Portuguese Citizen Card Authority
        and under the root of state Authority
        :param cert: Certificate from a Portuguese Citizen Card
        :return:-True : If the certificate is valid under the specifications mentioned before
                -False: If the certificate is invalid under the specifications mentioned before
        """

        if cert is None:
            return None

        storecontext = None
        try:
            certx509 = load_certificate(FILETYPE_PEM, cert)
            storecontext = X509StoreContext(self.ccStoreContext, certx509).verify_certificate()
        except X509StoreContextError as strerror:
            self.mylogger.log(ERROR,
                              "Impossible to verify the certificate given for the store context: \n{:s}".format(
                                  strerror.__doc__))
            return False
        except Error as strerror:
            self.mylogger.log(ERROR,
                              "The certificate to be verified wasn't loaded: \n Error Information:{:s}".format(
                                  strerror.__doc__))
            return False

        if storecontext is None:
            if slot is None:
                self.mylogger.log(INFO,
                                  "The smartcard  was sucessfully verified")
            else:
                self.mylogger.log(INFO,
                              "The smartcard with the id: {:3d} was sucessfully verified".format(slot))
            return True
        else:
            return False

    def sign_data(self, slot, data):
        """
        This method signs a string using the Private Key of the Portuguese Citizen Card
        :param slot: number of the slot in which the smartcart is connected to
        :param data: string to be signed
        :return: signature: bytes of the message signed
        """
        label = "CITIZEN AUTHENTICATION KEY"

        session = self.sessions[slot]
        cipherMechnism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, "")

        if isinstance(data, str):
            try:
                privateKey = self.sessions[slot].findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                                                        (
                                                                        PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY")
                                                                        ]))[0]

                signedBytelist = session.sign(privateKey, data.encode(), cipherMechnism)
                self.mylogger.log(INFO,
                                  "The smartcard with the id: {:3d}\n Signed this Data: {:15s} \n Signature : {}".format(
                                      slot, data,
                                      bytes(signedBytelist)))
            except PyKCS11Error:
                self.mylogger.log(ERROR,
                                  "The smartcard with the id: {:3d} unexpectedly closed the session while trying to sign data".format(
                                      slot))
            except IndexError:
                self.mylogger.log(ERROR,
                                  "The smartcard with the id: {:3d} unexpectedly closed the session".format(
                                      slot))
            else:
                return bytes(signedBytelist)
        return None

    def verifySignature(self, cert, data, signature):
        """
        This method is used to verify the signature of a document/string signed using a certificate that was provided before.
        The certificate must pass the test of trust by verifying the Chain of Trust of the Portuguese Citizen Card
        :param cert: certificate from the Portuguese Citizen Card
        :param data: unsigned data from the owner of the Certificate
        :param signature: data that was signed using a Private Key from the Portuguese Citizen Card
        :return: -True : If the signature is from the owner of the Citizen Card which provided the certificate and that
                        was used to sign the data
                -False: If the signature is not from the owner of the Citizen Card which provided the certificate and
                        that was used to sign the data
        """
        cert = x509.load_pem_x509_certificate(cert, default_backend())
        pubk = cert.public_key()
        padding = _aspaadding.PKCS1v15()

        if not isinstance(pubk, rsa.RSAPublicKey):
            self.mylogger.log(ERROR, "The provided certificate doesn't have a RSA public Key")
            return False
        try:
            state = pubk.verify(
                signature,
                bytes(data.encode()),
                padding,
                hashes.SHA256(),
            )

        except InvalidSignature as strerror:
            self.mylogger.log(ERROR, "Invalid Signature %s".format(strerror.__doc__))
            return False
        except TypeError:
            self.mylogger.log(ERROR, "Invalid Signature %s".format(TypeError.__doc__))
            return False
        else:
            self.mylogger.log(INFO,
                              "The smartcard with the id: {:3d} signed data. Signature :\n{} \n Status: Signature "
                              "Verified".format(slot,signature))
            return True

    def logout(self, slot):
        try:
            session = self.sessions[slot]
            session.logout()
            session.closeSession()
        except PyKCS11Error as strerror:
            session.closeSession()
            self.mylogger.log(DEBUG,
                              " No open session found for slot with the id :{:2d} \nInfo : \n{:15s}".format(slot,
                                                                                                            strerror.__doc__))


if __name__ == '__main__':
    try:
        pteid = PortugueseCitizenCard()
        fullnames = pteid.getSmartcardsNames()

        slot = -1
        if len(pteid.sessions) > 0:
            temp = ''.join('Slot{:3d}-> Fullname: {:10s}\n'.format(i, fullnames[i]) for i in range(0, len(fullnames)))

            while slot < 0 or slot > len(pteid.sessions):
                slot = input("Available Slots: \n{:40s} \n\nWhich Slot do you wish to use? ".format(temp))
                if slot.isdigit():
                    slot = int(slot)
                else:
                    slot = -1
        for i in range(0, len(pteid.sessions)):
            if slot != i:
                pteid.sessions[i].closeSession()

        st1r = pteid.PTEID_GetCertificate(slot)

        print("\nIs this certificate valid: {:s}".format(str(pteid.verifyChainOfTrust(st1r))))

        pteid.login(slot)

        datatobeSigned = "Random Randomly String"
        signedData = pteid.sign_data(slot, datatobeSigned)

        print(datatobeSigned + "\n")
        if (pteid.verifySignature(pteid.PTEID_GetCertificate(slot), datatobeSigned, signedData)):
            print("Verified")

    except KeyboardInterrupt:
        pteid.logout(slot)
        pteid.sessions[slot].closeSession()

    else:
        pteid.logout(slot)
        pteid.sessions[slot].closeSession()