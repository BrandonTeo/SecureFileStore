"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def upload(self, name, value):
        rk = self.crypto.get_random_bytes(16) #Generate a random key to encrypt (name, value)
        iv = self.crypto.get_random_bytes(16) #Generate a random IV to do CBC block cipher encryption
        pk = self.pks.get_public_key(self.username) #Grab our RSA public key

        #Store the random key using asymmetric encryption with our RSA public key
        #We also need to hash our username and the filename 
        hashed_name_key = self.crypto.cryptographic_hash(self.username + name + "key",'SHA256')
        encrypted_key = self.crypto.asymmetric_encrypt(rk,pk)
        #Put away random key
        self.storage_server.put(hashed_name_key, encrypted_key)

        #Store the message we want to send using AES encryption in CBC mode followed by a MAC to ensure integrity of message
        hashed_name_message = self.crypto.cryptographic_hash(self.username + name + "message", 'SHA256')
        iv_value = iv + self.crypto.symmetric_encrypt(value, rk, 'AES', 'CBC', iv)
        mac = self.crypto.message_authentication_code(iv_value, rk, 'SHA256')
        self.storage_server.put(hashed_name_message, iv_value+mac)

        return True

    def download(self, name):
        #Obtain the encrypted random key associated to this filename
        hashed_name_key = self.crypto.cryptographic_hash(self.username + name + "key",'SHA256')
        encrypted_key = self.storage_server.get(hashed_name_key)
        if encrypted_key == None: #This means we never stored the key for this specific file before
            return None

        #Decrypt to get random key
        try: #if scrambled this will not work
            rk = self.crypto.asymmetric_decrypt(encrypted_key, self.private_key)
        except:
            raise IntegrityError

        #Obtain the message associated to this filename
        hashed_name_message = self.crypto.cryptographic_hash(self.username + name + "message", 'SHA256')
        #If no value exists for this filename, we return none
        if self.storage_server.get(hashed_name_message) == None:
            return None
        else:
            iv_value_mac = self.storage_server.get(hashed_name_message)
            iv_value, mac = iv_value_mac[:len(iv_value_mac)-64], iv_value_mac[len(iv_value_mac)-64:]

            try: #if scrambled this will not work
                testmac = self.crypto.message_authentication_code(iv_value, rk, 'SHA256')
            except:
                raise IntegrityError

            #verify integrity
            if testmac == mac:
                iv = iv_value[:32]
                value = iv_value[32:]
                return self.crypto.symmetric_decrypt(value, rk, 'AES', 'CBC', iv)
            else:
                raise IntegrityError

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
