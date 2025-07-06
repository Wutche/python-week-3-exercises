import struct
import hashlib

class CompactSizeEncoder:
    """
    Encodes an integer into Bitcoin's CompactSize format.
    This format is used to indicate the length of following data.

    Encoding rules:
    - If value < 0xFD (253), it is encoded as a single byte.
    - If value <= 0xFFFF (65535), it is encoded as 0xFD followed by the 2-byte little-endian value.
    - If value <= 0xFFFFFFFF (4294967295), it is encoded as 0xFE followed by the 4-byte little-endian value.
    - If value > 0xFFFFFFFF, it is encoded as 0xFF followed by the 8-byte little-endian value.
    """
    def encode(self, value: int) -> bytes:
        """
        Encodes a given integer value into CompactSize bytes.

        Args:
            value (int): The integer to encode.

        Returns:
            bytes: The CompactSize byte representation.

        Raises:
            ValueError: If the value is negative or exceeds u64 max.
        """
        if not isinstance(value, int) or value < 0:
            raise ValueError("Value must be a non-negative integer.")
        if value < 0xFD:
            return value.to_bytes(1, 'little')
        elif value <= 0xFFFF:
            return b'\xFD' + value.to_bytes(2, 'little')
        elif value <= 0xFFFFFFFF:
            return b'\xFE' + value.to_bytes(4, 'little')
        elif value <= 0xFFFFFFFFFFFFFFFF:
            return b'\xFF' + value.to_bytes(8, 'little')
        else:
            raise ValueError("Value too large for CompactSize encoding.")

class CompactSizeDecoder:
    """
    Decodes Bitcoin's CompactSize bytes into an integer.
    """
    def decode(self, data: bytes) -> tuple[int, int]:
        """
        Decodes a CompactSize integer from the beginning of a byte sequence.

        Args:
            data (bytes): The byte sequence to decode from.

        Returns:
            tuple[int, int]: A tuple containing the decoded integer value
                             and the number of bytes consumed.

        Raises:
            ValueError: If data is too short or has an invalid prefix.
        """
        if not data:
            raise ValueError("Data is too short to decode CompactSize.")

        first_byte = data[0]
        if first_byte < 0xFD:
            return first_byte, 1
        elif first_byte == 0xFD:
            if len(data) < 3:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:3], 'little'), 3
        elif first_byte == 0xFE:
            if len(data) < 5:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:5], 'little'), 5
        elif first_byte == 0xFF:
            if len(data) < 9:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:9], 'little'), 9
        else:
            raise ValueError("Invalid CompactSize prefix.")

class TransactionData:
    """
    A class to represent and manage simplified Bitcoin transaction data.
    Illustrates lists, dictionaries, tuples, unpacking, and various loop constructs.
    """
    def __init__(self, version: int = 1, lock_time: int = 0):
        self.version = version
        self.inputs = []  # List of dictionaries, each representing a transaction input
        self.outputs = [] # List of tuples, each representing a transaction output
        self.lock_time = lock_time
        self.metadata = {} # Dictionary for arbitrary transaction metadata

    def add_input(self, tx_id: str, vout_index: int, script_sig: str, sequence: int = 0xFFFFFFFF):
        """
        Adds a new transaction input using list.append() and a dictionary.

        Args:
            tx_id (str): The ID (hash) of the previous transaction.
            vout_index (int): The index of the output being spent in the previous transaction.
            script_sig (str): The unlocking script.
            sequence (int): The sequence number.
        """
        input_data = {
        "prev_txid": tx_id,
        "prev_vout": vout_index,
        "script_sig": script_sig,
        "sequence": sequence
     }
        self.inputs.append(input_data)
        print(f"Added input: {input_data}")

    def add_output(self, value_satoshi: int, script_pubkey: str):
        """
        Adds a new transaction output using list.append() and a tuple.

        Args:
            value_satoshi (int): The amount in satoshis.
            script_pubkey (str): The locking script.
        """
        output = (value_satoshi, script_pubkey)
        self.outputs.append(output)
        print(f"Added output: {output}")

    def get_input_details(self) -> list[dict]:
        """
        Retrieves details of all transaction inputs.
        Demonstrates 'for' loop and 'enumerate'.

        Returns:
            list[dict]: A list of input details.
        """
        detailed_inputs = []
        print("\n--- Input Details (using for and enumerate) ---")
        for idx, input_data in enumerate(self.inputs):
            print(f"Input {idx}")
            prev_txid = input_data.get("prev_txid")
            prev_vout = input_data.get("prev_vout")
            script_sig = input_data.get("script_sig")
            print(f"TXID: {prev_txid}, VOUT: {prev_vout}, SCRIPT: {script_sig}")
            detailed_inputs.append(input_data.copy())
        return detailed_inputs

    def summarize_outputs(self, min_value: int = 0) -> tuple[int, int]:
        """
        Summarizes transaction outputs, skipping or breaking based on conditions.
        Demonstrates 'while', 'continue', and 'break' loops.

        Args:
            min_value (int): Minimum satoshi value for an output to be included in sum.

        Returns:
            tuple[int, int]: Total satoshis in valid outputs and count of valid outputs.
        """
        total_satoshi = 0
        valid_outputs_count = 0
        index = 0
        print("\n--- Summarizing Outputs (using while, continue, break) ---")

        while index < len(self.outputs):
            value, script = self.outputs[index]
            if not isinstance(value, int) or value < 0:
                print(f"Skipping invalid output at index {index}: {value}")
                index += 1
                continue
            if value < min_value:
                print(f"Skipping output at index {index}: {value} < {min_value}")
                index += 1
                continue
            total_satoshi += value
            valid_outputs_count += 1
            print(f"Including output {index}: {value} satoshis")
            
            if total_satoshi > 1000000000:  # 1 billion satoshis
                print(f"Total satoshis exceeded 1 Billion. Breaking summarization.")
                break
            index += 1
        return (total_satoshi, valid_outputs_count)
            
        

    def update_metadata(self, new_data: dict):
        """
        Updates the transaction metadata using dictionary methods.

        Args:
            new_data (dict): A dictionary of new metadata to add/update.
        """
        self.metadata.update(new_data)
        print(f"Updated metadata: {self.metadata}")

    def get_metadata_value(self, key: str, default=None):
        """
        Retrieves a value from metadata using dict.get().
        """
        return self.metadata.get(key, default)

    def get_transaction_header(self) -> tuple:
        """
        Returns core transaction header elements.
        Demonstrates simple tuple creation and returning.
        """
        return (self.version, len(self.inputs), len(self.outputs), self.lock_time)

    def set_transaction_header(self, version: int, num_inputs: int, num_outputs: int, lock_time: int):
        """
        Sets transaction header elements using multiple assignment.
        Note: num_inputs and num_outputs here are for demonstration of multiple assignment
        and wouldn't typically directly set list lengths in a real scenario.
        """
        self.version, self.lock_time = version, lock_time
        print(f"Set header via multiple assignment: version={version}, lock_time={lock_time}")

class UTXOSet:
    """
    Manages a set of Unspent Transaction Outputs (UTXOs).
    Illustrates Python's `set` data structure and its methods.

    UTXOs are represented as tuples: (transaction_id_hex, vout_index, amount_satoshi).
    """
    def __init__(self):
        self.utxos = set() # Set to store unique UTXO tuples

    def add_utxo(self, tx_id: str, vout_index: int, amount: int):
        """
        Adds a UTXO to the set.
        """
        utxo = (tx_id, vout_index, amount)
        self.utxos.add(utxo)
        print(f"Added UTXO: {utxo}")

    def remove_utxo(self, tx_id: str, vout_index: int, amount: int) -> bool:
        """
        Removes a UTXO from the set if it exists.

        Returns:
            bool: True if removed, False otherwise.
        """
        utxo = (tx_id, vout_index, amount)
        if utxo in self.utxos:
            self.utxos.remove(utxo)
            print(f"Removed UTXO: {utxo}")
            return True
        print(f"UTXO not found: {utxo}")
        return False

    def get_balance(self) -> int:
        """
        Calculates the total balance from all UTXOs in the set.
        """
        return sum(amount for _, _, amount in self.utxos)

    def find_sufficient_utxos(self, target_amount: int) -> set:
        """
        Finds a subset of UTXOs that sum up to at least the target amount.
        Demonstrates set operations (creating a new set).

        Args:
            target_amount (int): The amount needed.

        Returns:
            set: A set of UTXOs that fulfill the amount, or empty set if not possible.
        """
        selected = set()
        running_total = 0
        for utxo in sorted(self.utxos, key=lambda x: x[2]):
            selected.add(utxo)
            running_total += utxo[2]
            if running_total >= target_amount:
                print(f"Found sufficient UTXOs: {selected}")
                return selected
        print(f"Could not find sufficient UTXOs for target {target_amount}")
        return set()


    def get_total_utxo_count(self) -> int:
        """
        Returns the number of UTXOs in the set.
        Demonstrates `len()` on a set.
        """
        return len(self.utxos)

    def is_subset_of(self, other_utxo_set: 'UTXOSet') -> bool:
        """
        Checks if this UTXO set is a subset of another.
        Demonstrates set.issubset().
        """
        return self.utxos.issubset(other_utxo_set.utxos)

    def combine_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        """
        Combines two UTXO sets
        """
        combined = UTXOSet()
        combined.utxos = self.utxos.union(other_utxo_set.utxos)
        return combined

    def find_common_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        """
        Finds UTXOs common to two sets using set.intersection().
        """
        common = UTXOSet()
        common.utxos = self.utxos.intersection(other_utxo_set.utxos)
        return common

def generate_block_headers(
    prev_block_hash: str,
    merkle_root: str,
    timestamp: int,
    bits: int,
    start_nonce: int = 0,
    max_attempts: int = 1000
):
    """
    A generator function that simulates generating block headers by incrementing the nonce.
    This demonstrates the concept of proof-of-work attempts.

    Args:
        prev_block_hash (str): The hash of the previous block.
        merkle_root (str): The Merkle root of the transactions.
        timestamp (int): The block timestamp.
        bits (int): The target difficulty in compact form.
        start_nonce (int): The starting nonce.
        max_attempts (int): Maximum number of nonces to try.

    Yields:
        dict: A dictionary representing a potential block header, including the current nonce.
    """
    print(f"\n--- Generating Block Headers (using generator) ---")
    nonce = start_nonce
    attempts = 0
    while attempts < max_attempts:
        header_data = {
            "version": 1,
            "prev_block_hash": prev_block_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce
        }
        
        header_str = str(header_data)
        simulated_hash = hashlib.sha256(header_str.encode()).hexdigest()

        print(f"Attempt {attempts + 1}: Nonce {nonce}, Hash: {simulated_hash[:8]}...")
 
        yield header_data
 
        nonce += 1
        attempts += 1
 
        if attempts % 100 == 0 and attempts > 0:
            print(f"... {attempts} attempts made ...")