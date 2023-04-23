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
    LE = sys.byteorder == "little"

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
        data += "\0"
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
        if not os.path.isfile(self.BCH_PATH): return False
        with open(self.BCH_PATH, "rb") as file:
            data = file.read(self.BLOCK_LENGTH)
            if not data or len(data) != 76:
                raise Exception("Invalid file provided.")
            l = list(struct.unpack(self.BLOCK_FORMAT, data))
            state = l[4].decode().rstrip("\x00")
            return state == State.INITIAL.value
    
    def write_block(
            self,
            case_id: str,
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
        if self.LE:
            case_id = case_id.bytes_le
        else:
            case_id = case_id.bytes
        state = state.ljust(12, "\x00").encode()
        data += "\0"
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
                        "case_id": UUID(bytes_le=l[2]) if self.LE else UUID(bytes=l[2]),
                        "item_id": l[3],
                        "state": state,
                        "data_length": l[5]
                    }
                block['data'] = file.read(block['data_length']).decode()[:-1]
                res.append(block)

    def get_block(self, item_id):
        """
        Returns a a dictionary representation of the block, or None in case the item wasn't previously added.
        """
        for block in reversed(self.read_blocks()):
            if block['item_id'] == item_id:
                return block
        return None
    
    def verify_chain(self):
        """
        Performs verification based on the required errors.
        :return: An integer containing the number of transactions, a string that can be one of the following values:
        "NO PARENT", "DUPLICATE PARENT" or "IMPROPER REMOVAL", and a hash of one (or two in case of "DUPLICATE PARENT")
        blocks involved in error.
        """
        with open(self.BCH_PATH, "rb") as file:
            previous_hash = None
            transaction_number = 0
            parent_dict = {}
            removed_items = []
            err = None
            while True:
                block_binary = file.read(self.BLOCK_LENGTH)
                if not block_binary:
                    return transaction_number, err
                transaction_number += 1
                block = list(struct.unpack(self.BLOCK_FORMAT, block_binary))
                parent_hash = block[0].hex()
                data_len = block[5]
                data = file.read(data_len)
                # Check for parent
                current_hash = hashlib.sha256(block_binary + data).hexdigest()
                if previous_hash is not None and parent_hash != previous_hash:
                    err = "NO PARENT", current_hash
                # Check for linear structure
                if parent_hash in parent_dict:
                    err = "DUPLICATE PARENT", parent_dict[parent_hash], current_hash
                else:
                    parent_dict[parent_hash] = current_hash
                # Check for item traversal
                item_id = block[3]
                state = block[4].decode().rstrip("\x00")
                if state in {State.DISPOSED.value, State.RELEASED.value, State.DESTROYED.value}:
                    removed_items.append(item_id)
                elif (state in {State.CHECKED_IN.value, State.CHECKED_OUT.value}) and item_id in removed_items:
                    err = "IMPROPER REMOVAL", current_hash
                previous_hash = current_hash

        
    def __init__(self):
        """
        Creates the INITIAL block and updates the last hash.
        """
        if not self.check_init():
            self.__write_initial_block()
        else:
            self.last_hash = self.__get_last_hash()

# A simple main method that creates a chain with one item and performs some basic operations on it.
if __name__ == "__main__":
    bchain = Blockchain()
    for block in bchain.read_blocks():
        print(block)
    print(bchain.verify_chain())