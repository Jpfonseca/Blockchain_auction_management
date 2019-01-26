from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.exceptions import *

from os import listdir

from logging import DEBUG, ERROR, INFO
from log import LoggyLogglyMcface


class GenerateCertificates:
    """
    Class to deal with x.509 certificates.
    Generation of RSA private key and posterior generation of a certificate
    Generation Public key from certificate upon request
    """

    def __init__(self, create=True, name=None, password=None):
        """
        This module specifies if we will be creating a new Private Key or if we are loading a existing one.
        By default it creates a new Private Key
        :param create:- True(default) - create new Private Key
                      - False - load Private Key from file
                      type : boolean
        :param name:Specifies the name of the file where the Private key is stored, if the load option is selected.
                    The name doesn't need to have the extension of the file associated
                    type : String
        :param password: If the private key was stored using a Rsa encryption with a password
                        type : String
        """
        self.mylogger = LoggyLogglyMcface(name=GenerateCertificates.__name__)
        self.mylogger.log(INFO, "Entering GenerateCertificates")
        self.certPath = "./serverCerts/"
        self.extension = ".pem"

        if create:
            self.privateKey = self._generatePrivateKey()
        else:
            if name is not None and isinstance(name, str):
                if password is None:
                    self.privateKey = self.loadPrivateKeyFromFile(name, password=None)
                else:
                    self.privateKey = self.loadPrivateKeyFromFile(name, password=password)

            else:
                self.privateKey = None

        if self.privateKey is None:
            m = input("No private key found\nDo you wish to create a privatekey? Send y or Y to create")
            if m == "Y" or m == "y":
                self.privateKey = self._generatePrivateKey()
            else:
                return

        self.publicKey = self._getPubkeyFromPrivatekey()

    def checkExistence(self, name):
        certName = self.certPath + name + self.extension

        for filename in listdir(self.certPath):
            if certName == filename:
                return True
        return False

    def _generatePrivateKey(self):
        """
        This method generates a 4096 bytes private key using the RSA backend
        :return: _RSAPrivateKey Object
        """
        privatekey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        return privatekey

    def writePrivateKeyToFile(self, name, password=None):
        """
        This method will write a private key stored in the variable self.privateKey into a file using the following parameters for the name and encryption
        :param name: Specifies the name of the file where the Private key is stored, if the load option is selected.
                    The name doesn't need to have the extension of the file associated
                    type : String
        :param password: If the private key was stored using a Rsa encryption with a password
                        type : String
        :return:
        """
        if (password is not None) and isinstance(password, str):
            pemprivateKey = self.privateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(bytes(password.encode()))
            )
        else:
            pemprivateKey = self.privateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        certName = self.certPath + name + self.extension

        with open(certName, 'wb') as f:
            f.write(pemprivateKey)

    def loadPrivateKeyFromFile(self, name, password=None):
        """
        This method will load a Private Key from  a given file into  the variable self.privateKey
        :param name:Specifies the name of the file where the Private key is stored, if the load option is selected.
                    The name doesn't need to have the extension of the file associated
                    type : String
        :param password:If the private key was stored using a Rsa encryption with a password
                        type : String
        :return:
        """
        certName = self.certPath + name + self.extension

        with open(certName, "rb") as keyFile:
            if password is None:
                privateKey = serialization.load_pem_private_key(
                    keyFile.read(),
                    backend=default_backend(),
                    password=password
                )
            else:
                privateKey = serialization.load_pem_private_key(
                    keyFile.read(),
                    password=bytes(password.encode()),
                    backend=default_backend()
                )
        self.privateKey = privateKey
        self.publicKey = self._getPubkeyFromPrivatekey()

    def _getPubkeyFromPrivatekey(self):
        """
        This private method will generate a _RSAPublicKey Object from a given  _RSAPrivateKey stored in the variable self.privateKey
        :return: _RSAPublicKey
        """
        return self.privateKey.public_key()

    def writePublicKeyToFile(self, name):
        """
        This method will write a public key stored in the variable self.privateKey into a file using the following
        parameters for the name of the file.
        :param name: Specifies the name of the file where the Private key is stored, if the load option is selected.
                    The name doesn't need to have the extension of the file associated
                    type : String
        :return:
        """
        certName = self.certPath + name + self.extension

        with open(certName, 'wb') as f:
            f.write(self.publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def publicKeyToBytes(self):
        """
        This method will transform a _RSAPublicKey Object into bytes
        :return: public bytes of the public key
        """
        return self.publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def signData(self, data):
        if isinstance(data, str):
            data = data.encode()

        signature = self.privateKey.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

class CertificateOperations:
    def __init__(self):
        self.mylogger = LoggyLogglyMcface(name=CertificateOperations.__name__)
        self.mylogger.log(INFO, "Entering Certificate Operations")
        self.certName = "cert"
        self.certPath = "./userCerts/"
        self.certExtension = ".pem"
        self.availableCerts = self._loadAllCertsAsDict()
        self.cert = None

    def _loadAllCertsAsDict(self):
        """
        Load all certificates as a dictionary. One can search the certificates available by using a user id
        :return: dictionary of {{id:certificate_as_bytes}}
        """
        filenames = []
        for filename in listdir(self.certPath):
            if self.certExtension in filename:
                filenames = filenames + [filename]
        dict = {}
        for filename in filenames:
            id = filename.split(self.certExtension)[0].split(self.certName)[1]
            dict[id] = self.loadFromFile(int(id))
            self.mylogger.log(INFO, "The certificates available are : \n{}\n".format(dict))
        return dict

    def loadFromFile(self, id, certPath=None):
        """
        This method fetches a certificate from a file and transforms it into bytes
        :return:
        """
        if certPath == None:
            certPath = self.certPath
        certname = certPath + self.certName + str(id) + self.certExtension
        with open(certname, 'rb') as f:
            content = f.read()
        self.mylogger.log(INFO, "The certificate loaded was : \n{}\n".format(content))
        return content

    def writeToFile(self, cert, id):
        """
        Method to write a certificate in bytes to a file called "cert{id}.pem" where {id} is the id of the user who has
        the certificate cert
        :param cert: certificate of a given user
        :param id: id of the user generated by the Manager
        :return:
        """
        certname = self.certPath + self.certName + str(id) + self.certExtension
        with open(certname, 'wb') as f:
            f.write(cert)

        self.mylogger.log(INFO, "The certificate written to {}  was : \n{}\n".format(certname, cert))
        self.availableCerts = self._loadAllCertsAsDict()

    def getCertfromPem(self, cert):
        self.cert = x509.load_pem_x509_certificate(cert, default_backend())

    def getPubKey(self):

        pubk = self.cert.public_key()
        return pubk

    def rsaPubkToPem(self, pubk):
        if isinstance(pubk, rsa.RSAPublicKey):
            return pubk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return None


class CryptoUtils:
    def __init__(self):
        self.mylogger = LoggyLogglyMcface(name=CryptoUtils.__name__)
        self.mylogger.log(INFO, "Entering CryptoUtils")
    # Operations over the generated keys
    def loadPubk(self, pubk):
        if isinstance(pubk, str):
            pubk = pubk.encode()
        return serialization.load_pem_public_key(pubk, default_backend())

    def verifySignatureCC(self, pubk, data, signature):
        """
        This method will receive a _RSAPublicKey object and test if the signature provided (bytes) corresponds to the owner of that public key
        :param pubk: _RSAPublicKey object
        :param data: data to check
                    type: string
        :param signature: signature to verify
                :type bytes
        :return:
        """
        padding = _aspaadding.PKCS1v15()

        if not isinstance(pubk, rsa.RSAPublicKey):
            if isinstance(pubk, bytes) or isinstance(pubk, str):
                pubk = self.loadPubk(pubk)
            else:
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
            return True

    def verifySignatureServers(self, pubk, data, signature):
        """
        This method will receive a _RSAPublicKey object and test if the signature provided (bytes) corresponds to the owner of that public key
        :param pubk: _RSAPublicKey object
        :param data: data to check
                    type: string
        :param signature: signature to verify
                :type bytes
        :return:
        """
        if not isinstance(pubk, rsa.RSAPublicKey):
            if isinstance(pubk, bytes) or isinstance(pubk, str):
                pubk = self.loadPubk(pubk)
            else:
                self.mylogger.log(ERROR, "The provided certificate doesn't have a RSA public Key")
                return False
        try:
            state = pubk.verify(
                signature,
                bytes(data.encode()),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )

        except InvalidSignature as strerror:
            self.mylogger.log(ERROR, "Invalid Signature %s".format(strerror.__doc__))
            return False
        except TypeError:
            self.mylogger.log(ERROR, "Invalid Signature %s".format(TypeError.__doc__))
            return False
        else:
            return True


    def RSAEncryptData(self, pubK, data):
        """
        This method will receive a string and encrypt it with the public key stored in the
        :param data:data to be encrypted
                    type: string
        :return: encrypted data
                type:bytes
        """
        if isinstance(data, str):
            data = bytes(data.encode())
        encryptedData = pubK.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)

        )
        return encryptedData

    def RSADecryptData(self, privK, encryptedData):
        """
        This method will receive a bytes and decrypt them with the private key stored in the self.privateKey variable
        :param encryptedData:encrypted data
                type:bytes
        :return: original data
                    type: bytes
        """
        data = privK.decrypt(
            encryptedData,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )
        """
            The return value is bytes. Use data.decode() to convert to string
        """
        return data


if __name__ == '__main__':
    certops = CertificateOperations()
    cert = b'-----BEGIN CERTIFICATE-----\nMIIHOjCCBiKgAwIBAgIIffvt1b/siA8wDQYJKoZIhvcNAQEFBQAwgYQxQTA/BgNV' \
           b'\nBAMMOChUZXN0ZSkgRUMgZGUgQXV0ZW50aWNhw6fDo28gZG8gQ2FydMOjbyBkZSBD' \
           b'\naWRhZMOjbyAwMDA4MRQwEgYDVQQLDAtzdWJFQ0VzdGFkbzEcMBoGA1UECgwTQ2Fy' \
           b'\ndMOjbyBkZSBDaWRhZMOjbzELMAkGA1UEBhMCUFQwHhcNMTQwMjA3MDAwMjU3WhcN' \
           b'\nMTkwMjA2MDAwMDAwWjCBwzELMAkGA1UEBhMCUFQxHDAaBgNVBAoME0NhcnTDo28g' \
           b'\nZGUgQ2lkYWTDo28xHDAaBgNVBAsME0NpZGFkw6NvIFBvcnR1Z3XDqnMxKzApBgNV' \
           b'\nBAsMIihUZXN0ZSkgQXV0ZW50aWNhw6fDo28gZG8gQ2lkYWTDo28xETAPBgNVBAQM' \
           b'\nCFJldm9nYWRvMQwwCgYDVQQqDANBbmExEzARBgNVBAUTCkJJOTkwMDA2NDgxFTAT' \
           b'\nBgNVBAMMDEFuYSBSZXZvZ2FkbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\nzCte+VR8qEpdKxTIUp/04+8d7M7uJo2' \
           b'+QicINxCuArwzhCGuyPZ2qmDUGEv1QU24\n2tUlNsD9h32GKUVbblHJ2xQnavovRvOOepN7/E3mKt5y8J6qIg+jkxpDNgv+EjYn' \
           b'\nZ9sUKoGWkLc7ZCjtZKNF9tkKFfCWhincPW/x3BGGqTkCAwEAAaOCA/EwggPtMAwG\nA1UdEwEB/wQCMAAwDgYDVR0PAQH' \
           b'/BAQDAgOIMB0GA1UdDgQWBBS/J44L1UUfYBnw\nLNFSEp0uhoveUTAfBgNVHSMEGDAWgBS7UwhXSurYWIp7f+FdWjQkQGKhoTCCAg8G' \
           b'\nA1UdIASCAgYwggICMIHIBghghGwBAQECFDCBuzCBuAYIKwYBBQUHAgIwgasegagA' \
           b'\nTwAgAGMAZQByAHQAaQBmAGkAYwBhAGQAbwAgAGUAbQBpAHQAaQBkAG8AIABzAGUA' \
           b'\nZwB1AG4AZABvACAAZQBzAHQAYQAgAHAAbwBsAO0AdABpAGMAYQAgAOkAIAB1AHQA' \
           b'\naQBsAGkAegBhAGQAbwAgAHAAYQByAGEAIABhAHUAdABlAG4AdABpAGMAYQDnAOMA' \
           b'\nbwAgAGQAbwAgAEMAaQBkAGEAZADjAG8wfgYLYIRsAQEBAgQCAAcwbzBtBggrBgEF' \
           b'\nBQcCARZhaHR0cDovL3BraS50ZXN0ZS5jYXJ0YW9kZWNpZGFkYW8ucHQvcHVibGlj' \
           b'\nby9wb2xpdGljYXMvZHBjL2NjX3N1Yi1lY19jaWRhZGFvX2F1dGVudGljYWNhb19k' \
           b'\ncGMuaHRtbDA2BghghGwBAQECCjAqMCgGCCsGAQUFBwIBFhxodHRwOi8vd3d3LnNj' \
           b'\nZWUuZ292LnB0L3BjZXJ0MH0GDGCEbAEBAQIEAgABATBtMGsGCCsGAQUFBwIBFl9o' \
           b'\ndHRwOi8vcGtpLnRlc3RlLmNhcnRhb2RlY2lkYWRhby5wdC9wdWJsaWNvL3BvbGl0' \
           b'\naWNhcy9wYy9jY19zdWItZWNfY2lkYWRhb19hdXRlbnRpY2FjYW9fcGMuaHRtbDBx' \
           b'\nBgNVHR8EajBoMGagZKBihmBodHRwOi8vcGtpLnRlc3RlLmNhcnRhb2RlY2lkYWRh' \
           b'\nby5wdC9wdWJsaWNvL2xyYy9jY19zdWItZWNfY2lkYWRhb19hdXRlbnRpY2FjYW9f' \
           b'\nY3JsMDAwOF9wMDAwMS5jcmwwdwYDVR0uBHAwbjBsoGqgaIZmaHR0cDovL3BraS50' \
           b'\nZXN0ZS5jYXJ0YW9kZWNpZGFkYW8ucHQvcHVibGljby9scmMvY2Nfc3ViLWVjX2Np' \
           b'\nZGFkYW9fYXV0ZW50aWNhY2FvX2NybDAwMDhfZGVsdGFfcDAwMDEuY3JsMFEGCCsG' \
           b'\nAQUFBwEBBEUwQzBBBggrBgEFBQcwAYY1aHR0cDovL29jc3AuYXVjLnRlc3RlLmNh' \
           b'\ncnRhb2RlY2lkYWRhby5wdC9wdWJsaWNvL29jc3AwEQYJYIZIAYb4QgEBBAQDAgCg' \
           b'\nMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTk2MDA4MTkxMjAwMDBaMA0GCSqG\nSIb3DQEBBQUAA4IBAQBF7jYx156Fh8hoEs' \
           b'/m9Or5XOVmhbZ5nQyxUPNvtMmekJmr\nk7BPoBbUulcGHbD7/qO/BfZocWPm31YjX1vFATCJr7t9CRPv7u+J9WRbv5Lv2u0z' \
           b'\nc2hRgPVJKYzSAKKf6MWaP0AKSlqvLl1PPrXM5dxSOag5EJw/vadCNeDD1refidTq\nc4QiOJZ49NrWGSKm2HFmuj8p0dA+Wu4' \
           b'+O80HHixNF3jEvkGhNt2/9oMttipHWy15\ndWFpclLlS0gTHUHG5Fi4jIf5X7xjKCXpthynPweeRYiP7zqONYpKleapmxqa0b9k' \
           b'\nQTMntd7vkpZ115sapOnb3HIwynmpACIvKgPqSgE1\n-----END CERTIFICATE-----\n '
    certops.getCertfromPem(cert)
    print(certops.getPubKey())
    certops.writeToFile(cert, 1)
    r = certops.loadFromFile(1)
    print(r.decode())
    print(certops.availableCerts)

    certgen = GenerateCertificates()

    certgen.writePrivateKeyToFile("priKManager", password="Manager")
    certgen.loadPrivateKeyFromFile("priKManager", password="Manager")
    print(certgen.privateKey)
    print("\n")
    certgen.writePrivateKeyToFile("priKManager")
    certgen.loadPrivateKeyFromFile("priKManager")
    print(certgen.privateKey)

    certgen.writePublicKeyToFile("pubKManager")
    str1 = certgen.publicKeyToBytes()
    print(str1)

    encryptedText = certgen.RSAEncryptData("Testing test")
    text = certgen.RSADecryptData(encryptedText)
    print(text)
