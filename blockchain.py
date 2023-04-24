import os
import struct
from enum import Enum
from datetime import datetime, timezone
import hashlib
from uuid import UUID
from enum import Enum
import sys

class State(Enum):
    INITIAL = "INITIAL"
    CHECKED_IN = "CHECKEDIN"
    CHECKED_OUT = "CHECKEDOUT"
    DISPOSED = "DISPOSED"
    DESTROYED = "DESTROYED"
    RELEASED = "RELEASED"


class Blockchain:

    BLOCK_FORMAT = "=32sd16sI12sI"
    BLOCK_LENGTH = 76
    BYTE_ORDER = sys.byteorder

    if "BCHOC_FILE_PATH" in os.environ:
        BCH_PATH = os.environ.get("BCHOC_FILE_PATH")
    else:
        BCH_PATH = "C:\Projects\CSE469 Project\CSE469\chain.dat"

    def __get_last_hash(self):
        """
        Calculates hash of the last block, used when a previously created file is read
        """
        with open(self.BCH_PATH, "rb") as file:
            last_block = None
            while last_block is None:
                first_block_fields = file.read(self.BLOCK_LENGTH)
                if not first_block_fields:
                    return hashlib.sha256(curr_block).digest()
                data_len = list(struct.unpack(self.BLOCK_FORMAT, first_block_fields))[5]
                data = file.read(data_len)
                curr_block = first_block_fields + data

    def __write_initial_block(self):
        """
        Writes the initial block when the new file is created.
        """
        previous_block = bytearray([0] * 32)
        # timestamp = datetime.now(timezone.utc).timestamp()
        timestamp = 0
        case_id = bytearray([0] * 16)
        item_id = 0
        # state = "{:<12}".format(State.INITIAL.value).encode()
        state = State.INITIAL.value.ljust(12, "\x00").encode()
        data = "Initial block"
        data += "\x00"
        data_length = len(data)
        data = data.encode()
        d = struct.pack(self.BLOCK_FORMAT, previous_block, timestamp, case_id, item_id, state, data_length)
        with open(self.BCH_PATH, "ab") as file:
            file.write(d)
            file.write(data)
        self.last_hash = hashlib.sha256(d+data).digest()

    def check_init(self):
        """
        Checks for the INITIAL block.
        :return: True on existing.
        """
        with open(self.BCH_PATH, "rb") as file:
            data = file.read(self.BLOCK_LENGTH)
            if not data or len(data) != 76:
                return False
            l = list(struct.unpack(self.BLOCK_FORMAT, data))
            state = l[4].decode().rstrip("\x00")
            return state == State.INITIAL.value
    
    def write_block(
            self,
            case_id: UUID,
            item_id: int,
            state: str,
            data: str
            ):
        """
        Writes a new block on the blockchain.
        :param case_id: A valid UUID represented as a string.
        :param item_id: Integer that identifies a specific item. Ensure that they're unique.
        :param state: A string representation of one of the allowed states.
        :param data: A string of desired length. Do not pad with null bytes, it's done internally.
        :return: True on succesful write.
        """
        previous_block = self.last_hash
        timestamp = datetime.now(timezone.utc).timestamp()
        case_id = case_id.int.to_bytes(16, byteorder=self.BYTE_ORDER)
        state = state.ljust(12, "\x00").encode()
        data_length = len(data)
        data = data.encode()
        d = struct.pack(self.BLOCK_FORMAT, previous_block, timestamp, case_id, item_id, state, data_length)
        with open(self.BCH_PATH, "ab") as file:
            file.write(d)
            file.write(data)
        self.last_hash = hashlib.sha256(d+data).digest()
        return True

    def read_blocks(self):
        """"
        Returns a list of dictionaries representing blocks.
        The following fields are present:
            - previous_block: a hex string containing the hash of the previous block
            - timestamp: a datetime object containing the UTC-based time of writing
            - case_id: a UUID object representing ID of the case
            - item_id: an integer representing ID of an item
            - state: a string following the convention of the State enum
            - data_length: length of the description area, stored as integer
            - data: a string of defined length
        """
        res = []
        with open(self.BCH_PATH, "rb") as file:
            while True:
                data = file.read(self.BLOCK_LENGTH)
                if not data:
                    return res
                l = list(struct.unpack(self.BLOCK_FORMAT, data))
                state = l[4].decode().rstrip("\x00")
                if state == State.INITIAL.value:
                    block = {
                        "previous_block": None,
                        "timestamp": datetime.fromtimestamp(l[1]),
                        "case_id": None,
                        "item_id": None,
                        "state": state,
                        "data_length": l[5]
                    }
                else:
                    block = {
                        "previous_block": l[0].hex(),
                        "timestamp": datetime.fromtimestamp(l[1]),
                        # "case_id": UUID(bytes_le=l[2]) if self.LE else UUID(bytes=l[2]),
                        "case_id": UUID(int=int.from_bytes(l[2], byteorder=self.BYTE_ORDER)),
                        "item_id": l[3],
                        "state": state,
                        "data_length": l[5]
                    }
                block['data'] = file.read(block['data_length']).decode()
                res.append(block)

    def get_block(self, item_id):
        """
        Returns a a dictionary representation of the block, or None in case the item wasn't previously added.
        """
        for block in reversed(self.read_blocks()):
            if block['item_id'] == item_id:
                return block
        return None
    

    def verify_checksums(self):
        """
        Performs verification based on the required errors.
        :return: An integer containing the number of transactions, a string that can be one of the following values:
        "NO PARENT", "DUPLICATE PARENT" or "IMPROPER REMOVAL", and a hash of one (or two in case of "DUPLICATE PARENT")
        blocks involved in error.
        """
        with open(self.BCH_PATH, "rb") as file:
            previous_hash = None
            while True:
                block_binary = file.read(self.BLOCK_LENGTH)
                if not block_binary:
                    return True
                block = list(struct.unpack(self.BLOCK_FORMAT, block_binary))
                parent_hash = block[0].hex()
                data_len = block[5]
                data = file.read(data_len)
                # Check for parent
                current_hash = hashlib.sha256(block_binary + data).hexdigest()
                if previous_hash is not None and parent_hash != previous_hash:
                    return False
                previous_hash = current_hash


    def verify_valid(self):
        with open(self.BCH_PATH, "rb") as file:
            while True:
                block_binary = file.read(self.BLOCK_LENGTH)
                if not block_binary:
                    return True
                if len(block_binary) != 76:
                    return False
                block = list(struct.unpack(self.BLOCK_FORMAT, block_binary))
                data_len = block[5]
                data = file.read(data_len)
        


    def verify_remove_is_final(self):
        """
        Loops through the entire blockchain, keeping track of all items that have been removed. If an item that has been removed appears again, return False.
        Otherwise, return True.
        """
        blocks = self.read_blocks()
        removed = []
    
        for block in blocks:
            if block['item_id'] in removed:
                return False


            state = block['state']
            if state == "DISPOSED" or state == "DESTROYED" or state == "RELEASED":
                removed.append(block['item_id'])

        return True


    def verify_add_is_first(self):
        """
        Loops through the entire blockchain, checking every new item. If a new item has the status 'CHECKEDIN', then continue. If a new item has any other status, return False.
        Once the end of the chain has been reached with no returns, return True.
        """
        blocks = self.read_blocks()
        items = []

        # Remove the INITIAL block from the list
        blocks.pop(0)

        for block in blocks:
            if block['item_id'] not in items:
                if block['state'] != "CHECKEDIN":
                    return False
                else:
                    items.append(block['item_id'])

        return True


    def verify_releases_are_good(self):
        """
        Loops through the entire blockchain. Checks every item that is released to see if they have a valid reason (data_length > 0). Return false if an item is released without a reason.
        """
        blocks = self.read_blocks()

        for block in blocks:
            if block['state'] == "RELEASED" and block['data_length'] <= 0:
                return False

        return True


    def verify_status_good(self):
        """
        Loops through the entire blockchain. Checks every item to see if their status is valid (is in the State enum). Returns false is an invalid status is found.
        """
        blocks = self.read_blocks()
    
        states = ["INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]

        for block in blocks:
            status = block['state']
            if status not in states:
                return False

        return True


    def verify_check_order(self):
        """
        Loops through the entire blockchain. Checks if any item is checked out twice with no checkouts inbetween, and if any item is checked out twice iwth no checkins inbetween. Returns false if so.
        """
        blocks = self.read_blocks()

        checked_in = []
        checked_out = []

        for block in blocks:
            status = block['state']
            item_id = block['item_id']
            if status == "CHECKEDIN" and item_id in checked_in:
                return False
            elif status == "CHECKEDIN" and item_id not in checked_in:
                checked_in.append(item_id)
            elif status == "CHECKEDOUT" and item_id in checked_in:
                checked_in.remove(item_id)

            if status == "CHECKEDOUT" and item_id in checked_out:
                return False
            elif status == "CHECKEDOUT" and item_id not in checked_out:
                checked_out.append(item_id)
            elif status == "CHECKEDIN" and item_id in checked_out:
                checked_out.remove(item_id)

        return True


    def verify_duplicate_parents(self):
        """
        Returns false if multiple blocks have identical parents.
        """
        blocks = self.read_blocks()

        parents = []

        for block in blocks:
            parent = block['previous_block']
            
            if parent in parents:
                return False
            else:
                parents.append(block['previous_block'])

        return True



    def __init__(self):
        """
        Creates the INITIAL block and updates the last hash.
        """
        if not os.path.isfile(self.BCH_PATH):
            self.__write_initial_block()
        elif self.check_init() and self.verify_valid():
            self.last_hash = self.__get_last_hash()

# A simple main method that creates a chain with one item and performs some basic operations on it.
if __name__ == "__main__":
    bchain = Blockchain()
    for block in bchain.read_blocks():
        print(block)
    print(bchain.verify_chain())
