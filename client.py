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
import math


def path_join(*strings):
    """Joins a list of strings putting a "/" between each."""
    return '/'.join(strings)


def e_and_m(crypto, e_key, m_key, content):
    """Returns the ciphered string that we would send after encrypting and mac'ing"""
    iv = crypto.get_random_bytes(16)
    enc = crypto.symmetric_encrypt(content, e_key, 'AES', 'CBC', iv)
    mac = crypto.message_authentication_code(iv + enc, m_key, 'SHA256')
    return iv + enc + mac


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object, username):

        super().__init__(storage_server, public_key_server, crypto_object, username)

        self.threshold = 128

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
            toStore = e_and_m(self.crypto, enc_key, mac_key, to_json_string(directory))
            self.storage_server.put(k2, toStore)

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
            toStore = e_and_m(self.crypto, enc_key, mac_key, to_json_string(sdirectory))
            self.storage_server.put(k4, toStore)

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

    def createMTree(self, chunk_list, e_key, m_key, root_id=None):
        """Takes in a list of chunks of data and returns a list of id : node pairs to add to the server
           Size of chunk_list are powers of 2.
        """
        node_list = []
        # In first pass we create data nodes
        for chunk in chunk_list:
            id = self.crypto.get_random_bytes(16)
            node_list.append((id, chunk))

        curr_layer = []
        # In second pass we create nodes that have hash values and pointers to data nodes
        for pair in node_list:
            d = []
            d.append(self.crypto.cryptographic_hash(pair[1], 'SHA256'))
            d.append(len(pair[1]))
            d.append(pair[0])
            new_pair = (self.crypto.get_random_bytes(16), d)
            curr_layer.append(new_pair)

        # In this loop we create the tree
        upper_layer = []
        while True:
            if len(curr_layer) == 1 and len(upper_layer) != 0:
                upper_layer.append(curr_layer.pop(0))
                curr_layer = upper_layer
                upper_layer = []
            elif len(curr_layer) == 0 and len(upper_layer) == 1:
                node_list.append(upper_layer.pop(0))
                break
            elif len(curr_layer) == 0 and len(upper_layer) > 1:
                curr_layer = upper_layer
                upper_layer = []
            elif len(curr_layer) == 1 and len(upper_layer) == 0:
                node_list.append(curr_layer.pop(0))
                break

            pair1 = curr_layer.pop(0)
            pair2 = curr_layer.pop(0)
            node_list.append(pair1)
            node_list.append(pair2)

            # Create the parent of pair1 and pair2
            id = self.crypto.get_random_bytes(16)
            d = []
            h = self.crypto.cryptographic_hash(pair1[1][0] + pair2[1][0], 'SHA256')
            d.append(h)
            d.append(pair1[1][1] + pair2[1][1])  # This value for the root node should be the length of the file value
            d.append(pair1[0])
            d.append(pair2[0])
            upper_layer.append((id, d))

        return_list = []
        for i in range(len(node_list)):
            pair = node_list[i]
            if type(pair[1]) is list:
                if i == len(node_list) - 1:
                    if root_id is None:
                        return_list.append((pair[0], e_and_m(self.crypto, e_key, m_key, "[D] " + pair[0] + to_json_string(pair[1]))))
                    else:
                        return_list.append((root_id, e_and_m(self.crypto, e_key, m_key, "[D] " + root_id + to_json_string(pair[1]))))
                else:
                    return_list.append((pair[0], e_and_m(self.crypto, e_key, m_key, to_json_string(pair[1]))))
            else:
                return_list.append((pair[0], e_and_m(self.crypto, e_key, m_key, pair[1])))

        return return_list

    def grabData(self, lst, e_key, m_key):
        """lst is the list of the top root node"""
        if len(lst) == 3:  # We hit a leaf node
            pkt = self.storage_server.get(lst[2])
            # Split the packet into the encrypted stuff and the mac that came along with it
            iv_encrypted_value, mac = pkt[:len(pkt) - 64], pkt[len(pkt) - 64:]

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
            value = self.crypto.symmetric_decrypt(encrypted_value, e_key, 'AES', 'CBC', iv)
            return value

        else:  # Basically when len(lst) == 4
            pkt1 = self.storage_server.get(lst[2])
            pkt2 = self.storage_server.get(lst[3])
            # Split the packet into the encrypted stuff and the mac that came along with it
            iv_encrypted_value1, mac1 = pkt1[:len(pkt1) - 64], pkt1[len(pkt1) - 64:]
            iv_encrypted_value2, mac2 = pkt2[:len(pkt2) - 64], pkt2[len(pkt2) - 64:]

            # Recreate the mac using m_key and compare it with the one that came along with it
            try:
                testmac1 = self.crypto.message_authentication_code(iv_encrypted_value1, m_key, 'SHA256')
                testmac2 = self.crypto.message_authentication_code(iv_encrypted_value2, m_key, 'SHA256')
            except:
                raise IntegrityError
            if testmac1 != mac1 or testmac2 != mac2:
                raise IntegrityError

            # Split into iv and the encrypted file value and decrypt accordingly
            iv1 = iv_encrypted_value1[:32]
            iv2 = iv_encrypted_value2[:32]
            encrypted_value1 = iv_encrypted_value1[32:]
            encrypted_value2 = iv_encrypted_value2[32:]
            lst1 = from_json_string(self.crypto.symmetric_decrypt(encrypted_value1, e_key, 'AES', 'CBC', iv1))
            lst2 = from_json_string(self.crypto.symmetric_decrypt(encrypted_value2, e_key, 'AES', 'CBC', iv2))
            # print("left")
            # print(self.grabData(lst1, e_key, m_key))
            # print("right")
            # print(self.grabData(lst2, e_key, m_key))
            return self.grabData(lst1, e_key, m_key) + self.grabData(lst2, e_key, m_key)

    def resolve(self, uid, e_key, m_key, mode=None):
        """Follows [P]'s until we reach the a None or [D] and return the data"""
        while True:
            pkt = self.storage_server.get(uid)
            if pkt is None:
                return None

            elif pkt.startswith("[P]"):
                uid = pkt[4:]

            else:
                # Split the packet into the encrypted stuff and the mac that came along with it
                iv_encrypted_value, mac = pkt[:len(pkt) - 64], pkt[len(pkt) - 64:]

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
                value = self.crypto.symmetric_decrypt(encrypted_value, e_key, 'AES', 'CBC', iv)

                if value.startswith("[D]"):
                    if mode == "update":
                        return uid, e_key, m_key
                    else:
                        value = value[4:]
                        test_swap_check = value[:32]
                        value = value[32:]  # This value should be a json stringed list

                        if test_swap_check != uid:
                            raise IntegrityError

                        return self.grabData(from_json_string(value), e_key, m_key)

                uid = value[:32]
                e_key = value[32:64]
                m_key = value[64:]

    def chunkify(self, value):
        length = len(value)
        numChunks = 1

        if length < self.threshold:
            return [value]

        while length * 1.0 / numChunks > self.threshold:
            numChunks = numChunks * 2

        # We need to make sure each chunk is smaller than the threshold we set
        chunk_size = math.ceil(length * 1.0 / numChunks)

        start = 0
        end = chunk_size
        chunk_list = []

        while True:
            chunk_list.append(value[start:end])
            start += chunk_size
            end += chunk_size

            if end > length:
                chunk_list.append(value[start:])
                break

        return chunk_list

    def upload(self, name, value):
        """This method does two things depending on the situation: either create or update
           When name is a new filename and not stored in the user's directory, we generate 
           a new id for the file and create a mapping from name to id in the directory. Then, 
           we also store a mapping from id to the encryption of the corresponding file along 
           with an integrity check. This method will return True is upload is successful.
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

        # Check if we have this file in our directory and act accordingly
        tup = directory.get(name)
        if tup is None:  # Case when this is a new file
            # Generate (file_id, encryption_key, mac_key) tuple
            e_key = self.crypto.get_random_bytes(16)
            m_key = self.crypto.get_random_bytes(16)

            # Create an empty dictionary under this filename for our sharing directory
            sdirectory[name] = {}
            toStore = e_and_m(self.crypto, enc_key2, mac_key2, to_json_string(sdirectory))
            k2 = path_join(self.username, "sdir")
            self.storage_server.put(k2, toStore)

            # Store (file_id : encrypted_value) mapping into server
            # We include the encryption key in front to make sure we're safe from swapping attacks
            # We choose the encryption key because it is consistent throughout sharing
            lst = self.createMTree(self.chunkify(value), e_key, m_key)
            root_id = lst[-1][0]
            for pair in lst:
                self.storage_server.put(pair[0], pair[1])

            tup = (root_id, e_key, m_key)
            # Store (name : tuple) mapping into the directory, encrypt the directory and then store it to the server
            directory[name] = tup
            toStore = e_and_m(self.crypto, enc_key1, mac_key1, to_json_string(directory))
            k1 = path_join(self.username, "dir")
            self.storage_server.put(k1, toStore)

            return True

        else:  # Case when we are updating the file
            # Grab the corresponding values from the tuple
            file_id, e_key, m_key = tup[0], tup[1], tup[2]
            if self.resolve(file_id, e_key, m_key, "update") is not None:
                root_id, e_key, m_key = self.resolve(file_id, e_key, m_key, "update")
                root_pkt = self.storage_server.get(root_id)

                # Split the packet into the encrypted stuff and the mac that came along with it
                iv_encrypted_value, mac = root_pkt[:len(root_pkt) - 64], root_pkt[len(root_pkt) - 64:]

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
                v = self.crypto.symmetric_decrypt(encrypted_value, e_key, 'AES', 'CBC', iv)

                v = v[4:]
                test_swap_check = v[:32]
                v = v[32:]  # This value should be a json stringed list

                if test_swap_check != root_id:
                    raise IntegrityError

                root_lst = from_json_string(v)

                if len(value) != root_lst[1]:  # We can just replace i guess
                    # Store (file_id : encrypted_value) mapping into server
                    # We include the encryption key in front to make sure we're safe from swapping attacks
                    # We choose the encryption key because it is consistent throughout sharing
                    new_lst = self.createMTree(self.chunkify(value), e_key, m_key, root_id)
                    for pair in new_lst:
                        self.storage_server.put(pair[0], pair[1])

                else:  # We need to do efficient updates
                    # Create the merkle tree for this value
                    new_lst = self.createMTree(self.chunkify(value), e_key, m_key)
                    temp_dict = {}
                    temp_rootid = new_lst[-1][0]
                    for pair in new_lst:
                        temp_dict[pair[0]] = pair[1]

                    self.eff_update(temp_dict, temp_rootid, root_id, e_key, m_key, True)

                return True

    def eff_update(self, temp_dict, temp_rootid, root_id, e_key, m_key, status=False):
        temp_id = temp_rootid
        real_id = root_id

        enc_temp_list = temp_dict[temp_id]
        enc_real_list = self.storage_server.get(real_id)

        # Split the packet into the encrypted stuff and the mac that came along with it
        iv_encrypted_value1, mac1 = enc_temp_list[:len(enc_temp_list) - 64], enc_temp_list[len(enc_temp_list) - 64:]
        iv_encrypted_value2, mac2 = enc_real_list[:len(enc_real_list) - 64], enc_real_list[len(enc_real_list) - 64:]

        # Recreate the mac using m_key and compare it with the one that came along with it
        try:
            testmac1 = self.crypto.message_authentication_code(iv_encrypted_value1, m_key, 'SHA256')
            testmac2 = self.crypto.message_authentication_code(iv_encrypted_value2, m_key, 'SHA256')
        except:
            raise IntegrityError
        if testmac1 != mac1 or testmac2 != mac2:
            raise IntegrityError

        # Split into iv and the encrypted file value and decrypt accordingly
        iv1 = iv_encrypted_value1[:32]
        iv2 = iv_encrypted_value2[:32]
        encrypted_value1 = iv_encrypted_value1[32:]
        encrypted_value2 = iv_encrypted_value2[32:]
        dec1 = self.crypto.symmetric_decrypt(encrypted_value1, e_key, 'AES', 'CBC', iv1)
        dec2 = self.crypto.symmetric_decrypt(encrypted_value2, e_key, 'AES', 'CBC', iv2)

        if status:
            dec1 = dec1[4:]
            dec2 = dec2[4:]

            test_swap_check1 = dec1[:32]
            test_swap_check2 = dec2[:32]
            dec1 = dec1[32:]
            dec2 = dec2[32:]

            if test_swap_check1 != temp_id or test_swap_check2 != real_id:
                raise IntegrityError

        temp_list = from_json_string(dec1)
        real_list = from_json_string(dec2)

        if temp_list[0] != real_list[0]:
            if len(temp_list) == 3:
                link_id = real_list[2]
                replacement = temp_dict[temp_list[2]]
                self.storage_server.put(link_id, replacement)  # Replace the real encrypted data
                new_lst = to_json_string([temp_list[0], real_list[1], link_id])
                if status:
                    self.storage_server.put(real_id, e_and_m(self.crypto, e_key, m_key, "[D] " + real_id + new_lst))
                else:
                    self.storage_server.put(real_id, e_and_m(self.crypto, e_key, m_key, new_lst))
                return temp_list[0]
            else:
                temp_left_id = temp_list[2]
                temp_right_id = temp_list[3]
                real_left_id = real_list[2]
                real_right_id = real_list[3]

                hleft = self.eff_update(temp_dict, temp_left_id, real_left_id, e_key, m_key)
                hright = self.eff_update(temp_dict, temp_right_id, real_right_id, e_key, m_key)

                real_list[0] = self.crypto.cryptographic_hash(hleft + hright, 'SHA256')
                if status:
                    self.storage_server.put(real_id, e_and_m(self.crypto, e_key, m_key, "[D] " + real_id + to_json_string(real_list)))
                else:
                    self.storage_server.put(real_id, e_and_m(self.crypto, e_key, m_key, to_json_string(real_list)))

                return real_list[0]
        else:
            return real_list[0]

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
            return self.resolve(file_id, e_key, m_key)

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

        share_id = self.crypto.get_random_bytes(16)
        share_ekey = self.crypto.get_random_bytes(16)
        share_mkey = self.crypto.get_random_bytes(16)
        toStore = e_and_m(self.crypto, share_ekey, share_mkey, file_id + e_key + m_key)
        self.storage_server.put(share_id, toStore)

        # Store this sharing information into our sharing directory
        d = sdirectory[name]
        d[user] = (share_id, share_ekey, share_mkey)
        sdirectory[name] = d

        # Update this sharing directory back to the storage server
        toStore = e_and_m(self.crypto, enc_key2, mac_key2, to_json_string(sdirectory))
        self.storage_server.put(path_join(self.username, "sdir"), toStore)

        dst_pk = self.pks.get_public_key(user)
        msg = self.crypto.asymmetric_encrypt(share_id + share_ekey + share_mkey, dst_pk)
        sig = self.crypto.asymmetric_sign(msg, self.private_key)

        return msg + sig

    def receive_share(self, from_username, newname, message):
        """Agrees to the access granted from from_username and user will access this file using the filename 
           newname. First, we create a mapping from newname to an (id, encryption_key, mac_key) and store it 
           into user's directory. Then, we store the id : sharename mapping into the server. Recall that sharename
           is a [P].
        """
        if message is not None:  # Make sure that something is really shared to us
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

            # Verify the message
            msg = message[:512]
            sig = message[512:]

            # Test if our message aren't messed with
            if not self.crypto.asymmetric_verify(msg, sig, self.pks.get_public_key(from_username)):
                raise IntegrityError
            # If we reach here, we have verified that our message are good

            decrypted_value = self.crypto.asymmetric_decrypt(msg, self.private_key)
            share_id = decrypted_value[:32]
            share_ekey = decrypted_value[32:64]  # Got directory encryption key
            share_mkey = decrypted_value[64:]  # Got directory mac key

            # Generate (file_id, encryption_key, mac_key) tuple
            file_id = self.crypto.get_random_bytes(16)
            tup = (file_id, share_ekey, share_mkey)

            # Store a mapping of newname : tuple into directory, encrypt the directory and then store it into the server
            directory[newname] = tup # Replaces tup at newname even if it already has a value
            toStore = e_and_m(self.crypto, enc_key1, mac_key1, to_json_string(directory))
            k1 = path_join(self.username, "dir")
            self.storage_server.put(k1, toStore)

            # Store a mapping of id : sharename_pointer into the storage server
            self.storage_server.put(file_id, "[P] " + share_id)

            # Create an empty dictionary under this filename for our sharing directory
            sdirectory[newname] = {}
            toStore = e_and_m(self.crypto, enc_key2, mac_key2, to_json_string(sdirectory))
            k2 = path_join(self.username, "sdir")
            self.storage_server.put(k2, toStore)

    def revoke(self, user, name):
        """This method basically allows user to revoke any other user that he/she shared the file with.
           Once revoked, that user and every other person that he/she shared this file with will no longer 
           have access to the destination of the share chain, i.e. the real copy of the file.
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

        # Download our file and update our directory so that we can correctly upload our file again
        content = self.download(name)
        directory.pop(name)
        toStore = e_and_m(self.crypto, enc_key1, mac_key1, to_json_string(directory))
        k1 = path_join(self.username, "dir")
        self.storage_server.put(k1, toStore)
        self.upload(name, content)

        # Re-grab our directory
        directory = self.grab_directory(enc_key1, mac_key1)

        # Grab the tuple corresponding to the filename name
        tup = directory.get(name)
        if tup is None:  # Case when such tuple doesn't exist. Nothing to share here
            return None
        else:  # Case when such a tuple does exist
            # Grab the id that corresponds to this filename in the user's directory as well as the keys
            new_file_id, new_ekey, new_mkey = tup[0], tup[1], tup[2]

        # We delete user from our updates list and update the others
        d = sdirectory.get(name)
        d.pop(user)
        for k, v in d.items():
            share_id = v[0]
            share_ekey = v[1]
            share_mkey = v[2]
            toStore = e_and_m(self.crypto, share_ekey, share_mkey, new_file_id + new_ekey + new_mkey)
            self.storage_server.put(share_id, toStore)

        # Update our sharing directory with the revoked user revoked
        sdirectory[name] = d
        toStore = e_and_m(self.crypto, enc_key2, mac_key2, to_json_string(sdirectory))
        name = path_join(self.username, "sdir")
        self.storage_server.put(name, toStore)


