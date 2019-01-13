from logging import DEBUG, ERROR, INFO
import PyKCS11
from PyKCS11 import PyKCS11Error, PyKCS11Lib, Mechanism
from log import LoggyLogglyMcface

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

class PortugueseCitizenCard:

    def __init__(self):
        self.mylogger = LoggyLogglyMcface(name=PortugueseCitizenCard.__name__)
        self.mylogger.log(INFO, "Entering CC interface")

        self.lib = "libpteidpkcs11.so"
        self.cipher_mechanism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, "")
        self.sessions = self.__initPyKCS11__()

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
        :return: fullname of the person
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
            exit(10)
        else:
            try:
                infos1 = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in info][0])
            except (IndexError, TypeError):
                self.mylogger.log(ERROR,
                                  " Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(AUTH_CERT_LABEL))
                exit(12)
            else:
                names = infos1.split("BI")[1].split("\x0c")
                return ' '.join(names[i] for i in range(1,len(names)))


    def PTEID_GetCertificate(self,sessionIdx):
        AUTH_CERT_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

        self.mylogger.log(INFO, "Entering PTEID_GetCertificate with PyKCSS session id :{:2d}".format(sessionIdx))

        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL)]))
        except PyKCS11Error:
            self.mylogger.log(ERROR,
                              "The the smartcard with the id: {:3d} unexpectedly closed the session".format(
                                  sessionIdx))
            exit(12)
        else:
            try:

                der =bytes([c.to_dict()['CKA_VALUE'] for c in info][0])

            except (IndexError, TypeError):
                self.mylogger.log(ERROR,
                                  " Certificate \"{:15s}\" not found in PyKCSS session with the id :{:2d}".format(
                                      AUTH_CERT_LABEL))
                exit(12)
            else:
                # converting DER format to x509 certificate
                try:
                    cert= x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)
                except :
                    self.mylogger.log(ERROR,
                                      " Certificate for sessionID :{:2d} wasn't loaded: \n".format(sessionIdx))
                else:
                    self.mylogger.log(INFO,
                                  " Certificate for sessionID :{:2d} loaded:\n {:s}".format(sessionIdx,
                                      cert.decode("utf-8")))
                    return cert

if __name__ == '__main__':
    pteid = PortugueseCitizenCard()
    fullnames = [pteid.PTEID_GetID(i) for i in pteid.slots]

    slot = -1
    if len(pteid.sessions) > 0:
        temp = ''.join('Slot{:3d}-> Fullname: {:10s}\n'.format(i, fullnames[i]) for i in range(0, len(fullnames)))

        while slot < 0 or slot > len(pteid.sessions):
            slot = int(input("Available Slots: \n{:40s} \n\nWhich Slot do you wish to use? ".format(temp)))

    for i in range(0, len(pteid.sessions)):
        if slot != i:
            pteid.sessions[i].close()

    st1r=pteid.PTEID_GetCertificate(slot)
    pteid.sessions[slot].closeSession()