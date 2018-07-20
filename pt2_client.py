"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import to_json_string
from util import from_json_string


def path_join(*strings):
    """Joins a list of strings putting a "/" between each."""
    return '/'.join(strings)


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object, username):

        super().__init__(storage_server, public_key_server, crypto_object, username)

        k1 = path_join(self.username, "dir_keys")
        k2 = path_join(self.username, "dir")
        k3 = path_join(self.username, "sdir_keys")
        k4 = path_join(self.username, "sdir")

        # We only create a directory for the user if this is the first time the user uses the client
        if self.storage_server.get(k1) is None and self.storage_server.get(k2) is None:
            # Create keys to encrypt directory for user
            enc_key = self.crypto.get_random_bytes(16)
            mac_key = self.crypto.get_random_bytes(16)

            # Grab user's public key
            pub_key = self.pks.get_public_key(self.username)

            # Generate the encryption of the keys as well as the signature for it
            encryption = self.crypto.asymmetric_encrypt(enc_key + mac_key, pub_key)
            sig = self.crypto.asymmetric_sign(encryption, self.private_key)

            # Store the keys and their signature in the storage server
            self.storage_server.put(k1, encryption + sig)

            # Generate the encryption of the directory as well as a mac for it
            directory = {}
            iv = self.crypto.get_random_bytes(16)
            enc = self.crypto.symmetric_encrypt(to_json_string(directory), enc_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, mac_key, 'SHA256')
            self.storage_server.put(k2, iv + enc + mac)

        # We only create a sharing directory for the user if this is the first time the user uses the client
        if self.storage_server.get(k3) is None and self.storage_server.get(k4) is None:
            # Create keys to encrypt directory for user
            enc_key = self.crypto.get_random_bytes(16)
            mac_key = self.crypto.get_random_bytes(16)

            # Grab user's public key
            pub_key = self.pks.get_public_key(self.username)

            # Generate the encryption of the keys as well as the signature for it
            encryption = self.crypto.asymmetric_encrypt(enc_key + mac_key, pub_key)
            sig = self.crypto.asymmetric_sign(encryption, self.private_key)

            # Store the keys and their signature in the storage server
            self.storage_server.put(k3, encryption + sig)

            # Generate the encryption of the sharing directory as well as a mac for it
            sdirectory = {}
            iv = self.crypto.get_random_bytes(16)
            enc = self.crypto.symmetric_encrypt(to_json_string(sdirectory), enc_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, mac_key, 'SHA256')
            self.storage_server.put(k4, iv + enc + mac)

    def resolve(self, uid):
        """Follows [P]'s until we reach the a None or [D]"""
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[D]"):
                return uid
            elif res.startswith("[P]"):
                uid = res[4:]
            else:
                raise IntegrityError()

    def grab_directory_keys(self):
        """Returns the keys of this user for performing encryption and mac on his/her directory"""

        # Grab the public key of user
        pub_key = self.pks.get_public_key(self.username)

        # Grab the encrypted packet and divide it into the string of encrypted keys and signature
        packet = self.storage_server.get(path_join(self.username, "dir_keys"))
        encrypted_keys = packet[:512]
        sig = packet[512:]

        # Test if our encrypted keys aren't messed with
        if not self.crypto.asymmetric_verify(encrypted_keys, sig, pub_key):
            raise IntegrityError
        # If we reach here, we have verified that our keys are good

        decrypted_keys = self.crypto.asymmetric_decrypt(encrypted_keys, self.private_key)
        enc_key = decrypted_keys[:32]  # Got directory encryption key
        mac_key = decrypted_keys[32:]  # Got directory mac key

        return enc_key, mac_key

    def grab_sdirectory_keys(self):
        """Returns the keys of this user for performing encryption and mac on his/her sharing directory"""

        # Grab the public key of user
        pub_key = self.pks.get_public_key(self.username)

        # Grab the encrypted packet and divide it into the string of encrypted keys and signature
        packet = self.storage_server.get(path_join(self.username, "sdir_keys"))
        encrypted_keys = packet[:512]
        sig = packet[512:]

        # Test if our encrypted keys aren't messed with
        if not self.crypto.asymmetric_verify(encrypted_keys, sig, pub_key):
            raise IntegrityError
        # If we reach here, we have verified that our keys are good

        decrypted_keys = self.crypto.asymmetric_decrypt(encrypted_keys, self.private_key)
        enc_key = decrypted_keys[:32]  # Got directory encryption key
        mac_key = decrypted_keys[32:]  # Got directory mac key

        return enc_key, mac_key

    def grab_directory(self, enc_key, mac_key):
        """Returns the directory in the form of a dictionary of this user"""

        # Grab the encrypted packet and divide it into the encrypted part and the mac
        packet = self.storage_server.get(path_join(self.username, "dir"))
        iv_encrypted_dir, mac = packet[:len(packet)-64], packet[len(packet)-64:]

        # Recreate the mac using mac_key and compare it with the one that came along with it
        try:
            testmac = self.crypto.message_authentication_code(iv_encrypted_dir, mac_key, 'SHA256')
        except:
            raise IntegrityError
        if testmac != mac:
            raise IntegrityError
        # If we reach here, we have verified that our directory is good

        try:
            # Split iv_encrypted_dir into an iv and the encrypted_dir
            iv = iv_encrypted_dir[:32]
            encrypted_dir = iv_encrypted_dir[32:]
            # Decrypt and also convert back into a python dictionary
            directory = from_json_string(self.crypto.symmetric_decrypt(encrypted_dir, enc_key, 'AES', 'CBC', iv))
        except:
            raise IntegrityError

        return directory

    def grab_sdirectory(self, enc_key, mac_key):
        """Returns the sharing directory in the form of a dictionary of this user"""

        # Grab the encrypted packet and divide it into the encrypted part and the mac
        packet = self.storage_server.get(path_join(self.username, "sdir"))
        iv_encrypted_dir, mac = packet[:len(packet)-64], packet[len(packet)-64:]

        # Recreate the mac using mac_key and compare it with the one that came along with it
        try:
            testmac = self.crypto.message_authentication_code(iv_encrypted_dir, mac_key, 'SHA256')
        except:
            raise IntegrityError
        if testmac != mac:
            raise IntegrityError
        # If we reach here, we have verified that our directory is good

        try:
            # Split iv_encrypted_dir into an iv and the encrypted_dir
            iv = iv_encrypted_dir[:32]
            encrypted_dir = iv_encrypted_dir[32:]
            # Decrypt and also convert back into a python dictionary
            directory = from_json_string(self.crypto.symmetric_decrypt(encrypted_dir, enc_key, 'AES', 'CBC', iv))
        except:
            raise IntegrityError

        return directory

    def upload(self, name, value):
        """This method does two things depending on the situation: either create or update
           When name is a new filename and not stored in the user's directory, we generate 
           a new id for the file and create a mapping from name to id in the directory. Then, 
           we also store a mapping from id to the encryption of the corresponding file along 
           with an integrity check. This method will return True is upload is successful.
        """
        # Grab the directory keys of user
        keys = self.grab_directory_keys()
        enc_key = keys[0]
        mac_key = keys[1]

        # Grab the directory using the keys above
        directory = self.grab_directory(enc_key, mac_key)

        # Check if we have this file in our directory and act accordingly
        tup = directory.get(name)
        if tup is None:  # Case when this is a new file
            # Generate (file_id, encryption_key, mac_key) tuple
            file_id = self.crypto.get_random_bytes(16)
            e_key = self.crypto.get_random_bytes(16)
            m_key = self.crypto.get_random_bytes(16)
            tup = (file_id, e_key, m_key)

            # Store (name : tuple) mapping into the directory, encrypt the directory and then store it to the server
            directory[name] = tup
            iv = self.crypto.get_random_bytes(16)
            enc = self.crypto.symmetric_encrypt(to_json_string(directory), enc_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, mac_key, 'SHA256')
            name = path_join(self.username, "dir")
            self.storage_server.put(name, iv + enc + mac)

            # Store (file_id : encrypted_value) mapping into server
            k = path_join(self.username, "files", file_id)
            iv = self.crypto.get_random_bytes(16)
            # We include the encryption key in front to make sure we're safe from swapping attacks
            # We choose the encryption key because it is consistent throughout sharing
            swap_check = self.crypto.cryptographic_hash(e_key, 'SHA256')
            enc = self.crypto.symmetric_encrypt(swap_check + value, e_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, m_key, 'SHA256')
            self.storage_server.put(k, "[D] " + iv + enc + mac)

            return True

        else:  # Case when we are updating the file
            # Grab the corresponding values from the tuple
            file_id, e_key, m_key = tup[0], tup[1], tup[2]

            # Encrypt the updated values we want to replace the old values and replace it along with an integrity check
            # Make sure we get the end [D] file by using self.resolve
            k = self.resolve(path_join(self.username, "files", file_id))
            iv = self.crypto.get_random_bytes(16)
            # We include the encryption key in front to make sure we're safe from swapping attacks
            # We choose the encryption key because it is consistent throughout sharing
            swap_check = self.crypto.cryptographic_hash(e_key, 'SHA256')
            enc = self.crypto.symmetric_encrypt(swap_check + value, e_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, m_key, 'SHA256')
            self.storage_server.put(k, "[D] " + iv + enc + mac)

            return True

    def download(self, name):
        """This method will download the latest "version" of the file associated with name.
           Returns the value if it exists or None if it doesn't exist.
        """
        # Grab the directory keys of user
        keys = self.grab_directory_keys()
        enc_key = keys[0]
        mac_key = keys[1]

        # Grab the directory using the keys above
        directory = self.grab_directory(enc_key, mac_key)

        # Check if we have this file in our directory and act accordingly
        tup = directory.get(name)
        if tup is None:  # Case when the file associated to name doesn't exist
            return None
        else:  # Case when the file associated to name does exist
            # Grab the corresponding values from the tuple
            file_id, e_key, m_key = tup[0], tup[1], tup[2]

            # We grab the encrypted packet by following the share chain to the one that is under the owner's name
            pkt = self.storage_server.get(self.resolve(path_join(self.username, "files", file_id)))

            if pkt is None:  # Case when such a packet doesn't exist
                return None
            else:  # Case when the packet does exist
                # Skip "[D] "
                pkt = pkt[4:]

                # Split the packet into the encrypted stuff and the mac that came along with it
                iv_encrypted_value, mac = pkt[:len(pkt)-64], pkt[len(pkt)-64:]

                # Recreate the mac using m_key and compare it with the one that came along with it
                try:
                    testmac = self.crypto.message_authentication_code(iv_encrypted_value, m_key, 'SHA256')
                except:
                    raise IntegrityError
                if testmac != mac:
                    raise IntegrityError

                # Split into iv and the encrypted file value and decrypt accordingly
                iv = iv_encrypted_value[:32]
                encrypted_value = iv_encrypted_value[32:]
                swap_check_value = self.crypto.symmetric_decrypt(encrypted_value, e_key, 'AES', 'CBC', iv)

                # Test for swap attacks
                test_swap_check = swap_check_value[:64]
                value = swap_check_value[64:]
                if test_swap_check != self.crypto.cryptographic_hash(e_key, 'SHA256'):
                    raise IntegrityError

                return value

    def share(self, user, name):
        """Creates an intermediate sharename that can be deleted only by the user since it is tied to the id
           that is in the directory of this user. Then, stores a mapping of the sharename to a pointer that will 
           links to the destination of the real file. Returns a tuple with sharename and the keys needed to update
           or download this file.
        """
        # Grab the directory keys of user
        keys1 = self.grab_directory_keys()
        enc_key1 = keys1[0]
        mac_key1 = keys1[1]

        # Grab the sharing directory of this user
        keys2 = self.grab_sdirectory_keys()
        enc_key2 = keys2[0]
        mac_key2 = keys2[1]

        # Grab the directories of using the keys above
        directory = self.grab_directory(enc_key1, mac_key1)
        sdirectory = self.grab_sdirectory(enc_key2, mac_key2)

        # Grab the tuple corresponding to the filename name
        tup = directory.get(name)
        if tup is None:  # Case when such tuple doesn't exist. Nothing to share here
            return None
        else:  # Case when such a tuple does exist
            # Grab the id that corresponds to this filename in the user's directory as well as the keys
            file_id, e_key, m_key = tup[0], tup[1], tup[2]
            new_file_id = self.crypto.get_random_bytes(16)

        # Create sharename with the format: Alice/sharewith/Bob/16bitID
        sharename = path_join(self.username, "sharewith", user, new_file_id)
        # Remember to include "[P] "
        self.storage_server.put(sharename, "[P] " + path_join(self.username, "files", file_id))

        # Store this sharing information into our sharing directory
        sdirectory[user+name] = new_file_id
        # Update this sharing directory back to the storage server
        iv = self.crypto.get_random_bytes(16)
        enc = self.crypto.symmetric_encrypt(to_json_string(sdirectory), enc_key2, 'AES', 'CBC', iv)
        mac = self.crypto.message_authentication_code(iv + enc, mac_key2, 'SHA256')
        self.storage_server.put(path_join(self.username, "sdir"), iv + enc + mac)

        return sharename, e_key, m_key

    def receive_share(self, from_username, newname, message):
        """Agrees to the access granted from from_username and user will access this file using the filename 
           newname. First, we create a mapping from newname to an (id, encryption_key, mac_key) and store it 
           into user's directory. Then, we store the id : sharename mapping into the server. Recall that sharename
           is a [P].
        """
        if message is not None:  # Make sure that something is really shared to us
            # Grab the directory keys of user
            keys = self.grab_directory_keys()
            enc_key = keys[0]
            mac_key = keys[1]

            # Grab the directory using the keys above
            directory = self.grab_directory(enc_key, mac_key)

            # Generate (file_id, encryption_key, mac_key) tuple
            file_id = self.crypto.get_random_bytes(16)
            e_key = message[1]
            m_key = message[2]
            tup = (file_id, e_key, m_key)

            # Store a mapping of newname : tuple into directory, encrypt the directory and then store it into the server
            directory[newname] = tup # Replaces tup at newname even if it already has a value
            iv = self.crypto.get_random_bytes(16)
            enc = self.crypto.symmetric_encrypt(to_json_string(directory), enc_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, mac_key, 'SHA256')
            name = path_join(self.username, "dir")
            self.storage_server.put(name, iv + enc + mac)

            # Store a mapping of id : sharename_pointer into the storage server
            k = path_join(self.username, "files", file_id)
            self.storage_server.put(k, "[P] " + message[0])

    def revoke(self, user, name):
        """This method basically allows user to revoke any other user that he/she shared the file with.
           Once revoked, that user and every other person that he/she shared this file with will no longer 
           have access to the destination of the share chain, i.e. the real copy of the file.
        """
        # Grabs the sharing directory keys of user
        keys = self.grab_sdirectory_keys()
        enc_key = keys[0]
        mac_key = keys[1]

        # Grabs the sharing directory of user
        sdirectory = self.grab_sdirectory(enc_key, mac_key)

        # Grabs the file id of the corresponding user + name combo and make sure that it exists
        file_id = sdirectory.get(user+name)
        if file_id is not None:  # We are only able to revoke a user of a file if it exists
            # Generate the sharename that user wants to delete
            sharename = path_join(self.username, "sharewith", user, file_id)
            # Delete the sharename so that the shared user and the people they shared with cannot reach the destination
            # of the share chain anymore
            self.storage_server.delete(sharename)

            # Remove this sharing instance from the sdirectory and store it back into the storage server
            sdirectory.pop(user+name)
            iv = self.crypto.get_random_bytes(16)
            enc = self.crypto.symmetric_encrypt(to_json_string(sdirectory), enc_key, 'AES', 'CBC', iv)
            mac = self.crypto.message_authentication_code(iv + enc, mac_key, 'SHA256')
            name = path_join(self.username, "sdir")
            self.storage_server.put(name, iv + enc + mac)
