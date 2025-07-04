"""
This module defines classes for managing and interacting with data identifiers (DIDs).

Classes:
    - DidPayloadHistory: Represents the payload history associated with a DID request.
    - Interval: Represents a time interval associated with a DID request.
    - RequestID: A class representing the identification of a request.
    - DidRequest: Represents a data structure for a DID request, including request ID, response ID, DID, and associated information.
    - RequestList: Manages a list of DidRequest objects, reads DIDs from CSV files, and populates the request list.
    - DidRequestDatabase: Represents a database interface for storing and retrieving DidRequest objects.
"""

import os
import sqlite3
import json, csv
import time
import random
import math
import numpy as np
import pandas as pd
from collections import deque
from revcan.signal_discovery.utils.iso14229_1 import Iso14229_1
from revcan.signal_discovery.utils.iso15765_2 import IsoTp


class DidPayloadHistory:
    """
    A class representing the payload history of a DID (Data Identifier) request.

    Attributes:
        payload_list (deque): A deque to store the payload history.
        timestamp_list (deque): A deque to store the corresponding timestamps.
        changing_bits_count (int): Count of changing bits in the payload history.
        entropy (int): Entropy value calculated from the payload history.
        fft_result (None or ndarray): Result of the Fourier Transform.
        power_spectrum_density (int): Power spectrum density value.
        frequency_ratio (int): Frequency ratio value.

    Methods:
        __init__(self): Initializes an instance of the DidPayloadHistory class.
        __str__(self): Returns a string representation of the payload history.
    """

    HISTORY_MAX_LEN = 10

    def __init__(self):
        """
        Initialize a new instance of the `DidPayloadHistory` class.
        """
        self.payload_list = deque(maxlen=self.HISTORY_MAX_LEN)
        self.timestamp_list = deque(maxlen=self.HISTORY_MAX_LEN)
        self.changing_bits_count = 0
        self.entropy = 0
        self.fft_result = None
        self.power_spectrum_density = 0
        self.frequency_ratio = 0

    def __str__(self):
        """
        Return a string representation of the `DidPayloadHistory` instance.

        :return: A string representation of the payload and timestamp lists.
        :rtype: str
        """
        paired_list = list(zip(self.payload_list, self.timestamp_list))
        output = ""
        for payload, timestamp in paired_list:
            hex_str = " ".join([f"{b:02x}" for b in payload])
            timestamp_str = "[" + str(timestamp) + "] "
            output += timestamp_str + hex_str + "\n"
        # for byte_list in list(self.payload_list):
        #     hex_str = " ".join([f"{b:02x}" for b in byte_list])
        #     # hex_str = " ".join([hex(b) for b in byte_list])
        #     output += hex_str + "\n"
        return output


class Interval:
    """
    A class representing an interval.

    Attributes:
        _current (int): The current value of the interval.
        _last (int): The last value of the interval.
        minimum (int): The minimum allowed value for the interval.
        maximum (int): The maximum allowed value for the interval.

    Methods:
        __init__(self): Initializes an instance of the Interval class.
        __str__(self): Returns a string representation of the interval.
        current(self): Returns the current value of the interval.
        current(self, value): Sets the current value of the interval.
        update_current(self, value): Updates the current value of the interval.
    """

    DEFAULT_INTERVAL = 100
    MIN_INTERVAL = 1
    MAX_INTERVAL = 100

    def __init__(self):
        """
        Initialize a new instance of the `Interval` class with default values.
        """
        self._current = self.DEFAULT_INTERVAL
        self._last = self.DEFAULT_INTERVAL
        self.minimum = self.MIN_INTERVAL
        self.maximum = self.MAX_INTERVAL

    def __str__(self):
        """
        Return a string representation of the `Interval` instance.

        :return: A string representation of the current and last interval values.
        :rtype: str
        """
        return f"current: {self._current}, last: {self._last}"

    @property
    def current(self):
        return self._current

    @current.setter
    def current(self, value):
        self._current = value

    def update_current(self, value):
        self._last = self._current

        if value < self._current:
            value = round(value, 1)
        else:
            value = round(
                self._current
                + (1 - math.tanh(2.3 * (self._current / value))) * self._current,
                1,
            )

        if value < self.minimum:
            value = self.minimum
        if value > self.maximum:
            value = self.maximum
        self.current = value


class RequestID:
    """
    A class representing a request ID.

    Attributes:
        request_id (int): The request CAN ID.
        response_id (int): The response CAN ID.
        did (int): The data identifier to read.

    Methods:
        __init__(self, request_id, response_id, did): Initializes a new instance of the RequestID class.
        __str__(self): Returns a string representation of the RequestID instance.
    """

    def __init__(self, request_id: int, response_id: int, did: int) -> None:
        """
        Initialize a new instance of the `RequestID` class with the given request ID, response ID, and DID.

        :param request_id: The request CAN ID.
        :param response_id: The response CAN ID.
        :param did: The data identifier to read.
        """
        self.request_id = request_id
        self.response_id = response_id
        self.did = did

    def __str__(self):
        """
        Return a string representation of the `RequestID` instance.

        :return: A string representation of the request ID, response ID, and DID in hexadecimal format.
        :rtype: str
        """
        return f"{hex(self.request_id)}/{hex(self.response_id)}/{hex(self.did)}"


class DidRequest:
    """
    A class representing a DID (Data Identifier) request.

    Attributes:
        ids (RequestID): An instance of the RequestID class.
        interval (Interval): An instance of the Interval class.
        history (DidPayloadHistory): An instance of the DidPayloadHistory class.
        exec_time (float): Execution time for the request.
        execution_duration (float): Duration of the execution.
        blacklisted (bool): Indicates if the request is blacklisted.
        debug_history (list): A list to store debug information.

    Methods:
        __init__(self, request_id, response_id, did): Initializes a new instance of the DidRequest class.
        __str__(self): Returns a string representation of the DidRequest instance.
        list_to_bits(lst): Converts a list of integers to a binary number.
        is_positive_response(response): Returns a bool indicating whether the response is positive.
        get_value(wait_window): Sends a read data by identifier (DID) message and returns the response value.
        get_rnd_value(): Generates a random response value.
        make_unique_ID(): Creates a unique ID for the request.
        update_interval(minimum_length): Updates the interval based on the payload history length.
        calculate_new_interval(): Calculates a new interval based on payload history features.
        get_feature_sum(): Calculates the sum of payload history features.
        make_binary_list(request_history): Converts payload history to a list of binary numbers.
        calculate_payload_history_features(payload_copy): Calculates various features from the payload history.
        different_bits(payload_copy): Calculates the count of different bits between the saved payloads in the payload history.
        calculate_entropy(payload_copy): Calculates the entropy from the payload history.
        fourier_transform_history(payload_copy): Applies Fourier Transform to the payload history.
        calculate_power_spectrum_density(): Calculates power spectrum density.
        calculate_frequency_ratio(): Calculates frequency ratio.
        calculate_dominant_frequency_components(): Calculates dominant frequency components.
        append_to_debug_history(new_interval): Appends debug information to the debug history.
        dump_debug_history(): Dumps debug history to a CSV file.
    """

    def __init__(self, request_id: int, response_id: int, did: int):
        """
        Initialize a new instance of the `DidRequest` class with the given request ID, response ID, and DID.

        :param request_id: The request CAN ID.
        :param response_id: The response CAN ID.
        :param did: The data identifier to read.
        """
        self.ids: RequestID = RequestID(request_id, response_id, did)
        self.interval: Interval = Interval()
        self.history: DidPayloadHistory = (
            DidPayloadHistory()
        )  # initialize an instance of the `DidPayloadHistory` class
        self.exec_time = 0
        self.execution_duration = 0.03
        self.blacklisted = False
        self.feature_sum = 0
        self.debug_history = [
            [
                "timestamp",
                "interval",
                "bits",
                "entropy",
                "power_spectrum",
                "frequency_ratio",
                "blacklisted",
            ]
        ]

    def __str__(self):
        """
        Return a string representation of the `DidRequest` instance.

        :return: A string representation of the request ID, response ID, DID, interval, execution time, and blacklisted status.
        :rtype: str
        """
        return f"Request/Response/Data ID: [{hex(self.ids.request_id)}/{hex(self.ids.response_id)}/{hex(self.ids.did)}], Interval: [{self.interval}], Execution time: [{self.exec_time}], Blacklisted: {self.blacklisted}\nHistory:\n{self.history}"

    @staticmethod
    def list_to_bits(lst):
        """
        Convert the given list of integers to a single binary number.

        :param lst: a list of integers to convert
        :return: a binary number representing the concatenated binary strings of the integers in the list
        """
        binary_lst = [
            bin(x)[2:].zfill(8) for x in lst
        ]  # convert to binary and pad with zeros
        binary_str = "".join(binary_lst)  # concatenate binary strings
        # binary_num = int(binary_str, 2)  # convert to binary number
        return binary_str

    @staticmethod
    def is_positive_response(response):
        """
        Returns a bool indicating whether 'response' is positive

        :param response: ISO-14229-1 response data
        :return: False if response is a NEGATIVE_RESPONSE,
                 True otherwise
        """
        if response is not None and len(response) > 3 and response[0] != 0x7F:
            return True
        return False

    def get_value(self, wait_window=None):
        """
        Send read data by identifier (DID) messages to 'arb_id_request' and return the response value.

        :param arb_id_request: the arbitration ID for requests
        :param arb_id_response: the arbitration ID for responses
        :param did: the data identifier to read
        :return: the response value, or `None` if the response was not positive
        """

        with IsoTp(self.ids.request_id, self.ids.response_id) as tp:
            # Setup filter for incoming messages
            tp.set_filter_single_arbitration_id(self.ids.response_id)
            with Iso14229_1(tp) as uds:
                if wait_window is not None:
                    uds.P3_CLIENT = wait_window
                start_time = time.time()
                response = uds.read_data_by_identifier(identifier=[self.ids.did])
                self.execution_duration = time.time() - start_time
                if response:
                    pass
                else:
                    response = None
                # Only keep positive responses
                if response and self.is_positive_response(response):
                    # print(hex(self.ids.did))
                    # print(hex(self.list_to_bits([response[1], response[2]])))
                    # print(response)
                    # print(response[3:])
                    self.blacklisted = False
                    self.history.payload_list.append(response)
                    self.history.timestamp_list.append(time.time())
                    self.exec_time = time.time()
                    return response[3:], self.exec_time, self.make_unique_ID()
                else:
                    self.blacklisted = True
                    # If there was a negative response, append it to the payload history
                    if response:
                        self.history.payload_list.append(response)
                        self.history.timestamp_list.append(time.time())
                    self.exec_time = time.time()
                    self.interval.update_current(self.interval.maximum)
                    response = None
                    return response, self.exec_time, self.make_unique_ID()

    def get_rnd_value(self):
        # self.history.payload_list.append(random.randbytes(8))
        if len(self.history.payload_list) == 0:
            response = [random.randint(0, 255) for _ in range(random.randint(1, 16))]
        else:
            response = [
                random.randint(0, 255) for _ in range(len(self.history.payload_list[0]))
            ]
        time.sleep(random.randint(5, 15) / 1000)
        if random.randint(0, 10) == 0:
            response = None
        if response:
            self.history.payload_list.append(response)
            self.history.timestamp_list.append(time.time())
        self.exec_time = time.time()
        return response, self.exec_time, self.make_unique_ID()

    def make_unique_ID(self):
        return (
            str(hex(self.ids.request_id)[2:])
            + "_"
            + str(hex(self.ids.response_id)[2:])
            + "_"
            + str(hex(self.ids.did)[2:])
        )

    def update_interval(self, minimum_length=4):
        if len(self.history.payload_list) >= minimum_length and not self.blacklisted:
            if len(self.history.payload_list[0]) >= 4:
                new_interval = self.calculate_new_interval()
                self.interval.update_current(new_interval)
        else:
            self.interval.update_current(self.interval.maximum)

    def calculate_new_interval(self):
        copy_of_history_payload = self.history.payload_list
        self.calculate_payload_history_features(copy_of_history_payload)
        self.feature_sum = self.get_feature_sum()
        new_interval = self.interval.minimum + (((self.feature_sum) - 4) ** 2) * (
            (self.interval.maximum - self.interval.minimum) / 16
        )
        if new_interval > self.interval.maximum or copy_of_history_payload is []:
            new_interval = self.interval.maximum
        self.append_to_debug_history(new_interval)
        return new_interval

    def get_feature_sum(self):
        feature_sum = (
            self.history.changing_bits_count
            + self.history.entropy
            + self.history.power_spectrum_density
            + self.history.frequency_ratio
        )
        if feature_sum < 2.5:
            return feature_sum
        else:
            return 4

    def make_binary_list(self, request_history):
        binary_list = []
        for bytelist in request_history:
            bits = DidRequest.list_to_bits(bytelist[3:])
            binary_list.append(bits)
        return binary_list

    def calculate_payload_history_features(self, payload_copy):
        self.different_bits(payload_copy)
        self.calculate_entropy(payload_copy)
        self.fourier_transform_history(payload_copy)
        self.calculate_power_spectrum_density()
        self.calculate_frequency_ratio()

    def different_bits(self, payload_copy):
        binary_list = self.make_binary_list(payload_copy)
        total_different_bits = 0
        for binary1, binary2 in zip(binary_list, binary_list[1:]):
            for bit1, bit2 in zip(binary1, binary2):
                if bit1 != bit2:
                    total_different_bits += 1
        self.history.changing_bits_count = math.tanh(total_different_bits)

    def calculate_entropy(self, payload_copy):
        binary_list = self.make_binary_list(payload_copy)

        # Step 1: count the number of times each value appears in the sublist
        if binary_list == []:
            self.history.entropy = 0
            return 0
        counts = {}
        for value in binary_list:
            if value in counts:
                counts[value] += 1
            else:
                counts[value] = 1
        # Step 2: convert counts to probabilities
        total_values = len(binary_list)
        probabilities = {value: count / total_values for value, count in counts.items()}
        # Step 3: calculate entropy
        entropy = -sum(p * math.log2(p) for p in probabilities.values())
        self.history.entropy = math.tanh(entropy)

    def fourier_transform_history(self, payload_copy):
        binary_list = self.make_binary_list(payload_copy)
        concatenated_bit_string = "".join(binary_list)  # Concatenate all bit strings

        # Convert the concatenated string to an array of integers
        integer_array = np.array([int(bit) for bit in concatenated_bit_string])

        # Perform the Fourier Transform
        fourier_transform = np.fft.fft(integer_array)

        # Calculate the power spectrum
        power_spectrum = np.abs(fourier_transform) ** 2

        self.history.fft_result = power_spectrum[1 : (len(power_spectrum) // 2)]

    def calculate_power_spectrum_density(self):
        # Calculate the total power as the sum of all squared magnitudes
        power_spectrum_density = np.sum(np.abs(self.history.fft_result) ** 2)

        self.history.power_spectrum_density = math.tanh(power_spectrum_density)

    def calculate_frequency_ratio(self):
        (
            dominant_frequencies,
            dominant_magnitudes,
        ) = self.calculate_dominant_frequency_components()
        # Sort the magnitudes in descending order
        sorted_magnitudes = np.sort(dominant_magnitudes)[::-1]

        # Calculate the ratio between the highest and second highest magnitudes
        if sorted_magnitudes[1] == 0:
            frequency_ratio = 0
        else:
            frequency_ratio = sorted_magnitudes[0] / sorted_magnitudes[1]

        self.history.frequency_ratio = math.tanh(frequency_ratio)

    def calculate_dominant_frequency_components(self):
        # Find the indices of the highest magnitude peaks
        frequency_bins = np.arange(len(self.history.fft_result))
        sorted_indices = np.argsort(np.abs(self.history.fft_result))[::-1]

        # Extract the corresponding frequencies and magnitudes
        dominant_frequencies = frequency_bins[sorted_indices[:2]]
        dominant_magnitudes = np.abs(self.history.fft_result[sorted_indices[:2]])

        return dominant_frequencies, dominant_magnitudes

    def append_to_debug_history(self, new_interval):
        self.debug_history = self.debug_history + [
            [
                time.time(),
                new_interval,
                self.history.changing_bits_count,
                self.history.entropy,
                self.history.power_spectrum_density,
                self.history.frequency_ratio,
                self.blacklisted,
            ]
        ]

    def dump_debug_history(self):
        df = pd.DataFrame(self.debug_history[1:], columns=self.debug_history[0])
        script_directory = os.path.dirname(__file__)
        path = os.path.join(
            script_directory
            + "/tests/debug_history_dumps/{}_{}_debug_history_dump.csv".format(
                int(time.time()), self.make_unique_ID()
            )
        )
        df.to_csv(path, index=False, sep=",")


class RequestList:
    """
    A class for reading and storing data identifiers (DIDs) from *.db and *.csv files.

    Attributes:
        request_list (list): A list to store DidRequest objects.
        did_data (list): A list to store data identifiers and associated request-response pairs.
        count (int): Total number of requests.
        count_blacklisted (int): Number of blacklisted requests.
        count_not_blacklisted (int): Number of non-blacklisted requests.

    Methods:
        __init__(self): Initializes a new instance of the DidList class.
        __iter__(self): Initializes an iterator for the request list.
        __next__(self): Gets the next element in the iterator.
        __str__(self): Returns the string representation of the DidList instance.
        get_dids_from_csv_files(absolute_directory_path): Reads DIDs from CSV files in a directory.
        fill_request_list(): Fills the request list with DidRequest objects.
        fill_request_list_from_single_database_file(database_file_path, want_payload_history): Fills request list from a single database file.
        fill_request_list_from_database_files(absolute_directory_path, want_payload_history): Fills request list from multiple database files.
        count_requests(print_info): Counts the number of requests and blacklisted requests.
        create_did_obj(request_id, response_id, did): Creates a new DidRequest object.
    """

    def __init__(self):
        """
        Initializes a new instance of the DidList class.
        """
        self.request_list: list[DidRequest] = []
        self.did_data = []
        self.count = 0
        self.count_blacklisted = 0
        self.count_not_blacklisted = 0

    def __iter__(self):
        """
        Initialize the iterator for the `RequestList`.

        :return: The iterator object.
        """
        self.index = 0
        return self

    def __next__(self):
        """
        Get the next item from the iterator.

        :return: The next item in the iteration.
        :raises StopIteration: If there are no more items.
        """
        if self.index >= len(self.request_list):
            raise StopIteration
        value = self.request_list[self.index]
        self.index += 1
        return value

    def __str__(self):
        """
        Returns the string representation of the `RequestList` instance.

        :return: A string representation of all elements.
        :rtype: str
        """
        output = ""
        for did in self.request_list:
            output += str(did) + "\n"
        return output

    def get_dids_from_csv_files(self, absolute_directory_path):
        """
        Reads the data identifiers (DIDs) from files in the directory and returns them
        in a nested list of the following structure:
        [[['request_ID_0', 'responseID_0'], ['DID_0', 'DID_1', ...]], [['request_ID_1', 'responseID_1'], ['DID_0', 'DID_1', ...]], ...]

        :param absolute_directory_path: The absolute path to the directory containing the files.
        :return: a nested list of the DIDs and their associated request and response IDs
        :rtype: list
        """
        # Get the list of files in the DID directory
        files = os.listdir(absolute_directory_path)
        did_data = []
        # Loop through each file in the directory
        for file in files:
            # Get the request and response IDs from the filename
            arb_id_request = int(file.split("_")[1], 16)
            if file.split("_")[2][-4:] == ".txt":
                arb_id_response = int(file.split("_")[2][:-4], 16)
            else:
                arb_id_response = int(file.split("_")[2], 16)
            # Open the file and read the DIDs
            with open(os.path.join(absolute_directory_path, file), "r") as file:
                dids = []
                # Loop through each line in the file
                for line in file:
                    # If the line starts with "0x", extract the DID and value
                    if line.startswith("0x"):
                        did, value = line.strip().split(" ")
                        did = int(did, 16)
                        # If the value is not zero, add the DID to the list of DIDs
                        if value[4:] == "":
                            continue
                        value = int(value[4:], 16)
                        if value != 0:
                            dids.append(did)
                # If the list of DIDs is not empty, add the request-response pair and list of DIDs to the DID data list
                if dids == []:
                    continue
                canids = [arb_id_request, arb_id_response]
                did_data.append([canids, dids])
        self.did_data = did_data

    def fill_request_list(self):
        """
        Fills the `RequestList` instance's 'request_list' attribute with `DidRequest` objects created from the data in the 'did_data' parameter.
        """
        for entry in self.did_data:
            request_can_id, response_can_id = entry[0]
            dids = entry[1]
            # Create a DID object for each request-response pair and DID and add it to the DID list
            for did in dids:
                self.request_list.append(
                    self.create_did_obj(request_can_id, response_can_id, did)
                )

    def fill_request_list_from_single_database_file(
        self, database_file_path, want_payload_history: bool
    ):
        loaded_requests: list[DidRequest]
        count_duplicates = 0
        added_requests = set()
        with DidRequestDatabase(database_file_path) as db:
            loaded_requests = db.load_list(want_payload_history)
            for request in loaded_requests:
                if (
                    hex(request.ids.request_id)
                    + hex(request.ids.response_id)
                    + hex(request.ids.did)
                ) not in added_requests:
                    self.request_list.append(request)
                    added_requests.add(
                        hex(request.ids.request_id)
                        + hex(request.ids.response_id)
                        + hex(request.ids.did)
                    )
                else:
                    count_duplicates += 1
        print(f"Counted {count_duplicates} duplicates.")

    def fill_request_list_from_database_files(
        self, absolute_directory_path, want_payload_history: bool
    ):
        """
        Fill the request list of the instance with the requests stored in the DID database files located in the specified directory.

        Args:
            absolute_directory_path (str): The absolute path of the directory containing the DID database files.

        Returns:
            None

        Example usage:
            ```
            from autoudstool.dids import RequestList

            request_list = RequestList()
            absolute_directory_path = "/path/to/my/database/files"
            request_list.fill_request_list_from_database_files(absolute_directory_path)
            ```
        """
        loaded_requests: list[DidRequest]
        # Get the list of files in the DID directory
        files = (
            file
            for file in os.listdir(absolute_directory_path)
            if os.path.isfile(os.path.join(absolute_directory_path, file))
        )
        count_duplicates = 0
        added_requests = set()
        for file in files:
            database_file_path = os.path.join(absolute_directory_path, file)
            with DidRequestDatabase(database_file_path) as db:
                loaded_requests = db.load_list(want_payload_history)
                for request in loaded_requests:
                    if (
                        hex(request.ids.request_id)
                        + hex(request.ids.response_id)
                        + hex(request.ids.did)
                    ) not in added_requests:
                        self.request_list.append(request)
                        added_requests.add(
                            hex(request.ids.request_id)
                            + hex(request.ids.response_id)
                            + hex(request.ids.did)
                        )
                    else:
                        count_duplicates += 1
        print(f"Counted {count_duplicates} duplicates.")
        # self.interval.minimum = len(self.request_list) * 0.025

    def count_requests(self, print_info: bool = False):
        self.count = 0
        self.count_blacklisted = 0
        for request in self.request_list:
            self.count += 1
            if request.blacklisted:
                self.count_blacklisted += 1
        self.count_not_blacklisted = self.count - self.count_blacklisted
        if print_info:
            print(
                f"Total number of requests: {self.count},Number of blacklisted requests: {self.count_blacklisted}"
            )

    def create_did_obj(self, request_id, response_id, did):
        """
        Creates a new DidRequest object with the given request ID, response ID, and DID.

        :param request_id: the request ID for the DID request
        :param response_id: the response ID for the DID request
        :param did: the DID to request
        :type request_id: int
        :type response_id: int
        :type did: int
        :return: a new DidRequest object
        :rtype: DidRequest
        """
        did_obj = DidRequest(request_id, response_id, did)
        return did_obj


class DidRequestDatabase:
    """
    A class representing a database interface for storing and retrieving DidRequest objects.

    Attributes:
        db_file (str): The path to the database file.
        conn: The SQLite3 database connection.

    Methods:
        __init__(self, db_file): Initializes the class with the given database file path.
        __enter__(self): Creates the connection to the database and creates the table for storing DidRequest objects.
        __exit__(self, exc_type, exc_value, traceback): Closes the database connection when the context exits.
        reset_database(self): Resets the database by dropping the table.
        store_list(self, did_requests): Stores a list of DidRequest objects in the database.
        load_list(self): Retrieves a list of DidRequest objects from the database.
        export_db_as_csv(self): Exports the database to CSV files.
    """

    def __init__(self, db_file: str):
        """
        Initializes the class with the given database file path.

        :param db_file: The path to the database file.
        :type db_file: str
        """
        self.db_file = db_file
        self.conn = None

    def __enter__(self):
        """
        Creates the connection to the database and creates the table for
        storing DidRequest objects.
        """
        self.conn = sqlite3.connect(self.db_file)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS did_requests (
                                request_id INTEGER,
                                response_id INTEGER,
                                did INTEGER,
                                json_history_payload TEXT,
                                json_history_timestamp TEXT,
                                interval_current INTEGER,
                                exec_time INT
                            )"""
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Closes the database connection when the context exits.
        """
        if self.conn:
            self.conn.close()

    def reset_database(self):
        """
        Resets the database by dropping the existing table and creating a new one.
        """
        with self.conn:
            self.conn.execute("DROP TABLE IF EXISTS did_requests")
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS did_requests (
                                    request_id INTEGER,
                                    response_id INTEGER,
                                    did INTEGER,
                                    json_history_payload TEXT,
                                    json_history_timestamp TEXT,
                                    interval_current INTEGER,
                                    exec_time INT
                                )"""
            )

    def store_list(self, did_requests):
        """
        Stores a list of DidRequest objects in the database.

        :param did_requests: The list of DidRequest objects to be stored.
        :type did_requests: list
        """

        with self.conn:
            for request in did_requests:
                request: DidRequest
                json_history_payload = json.dumps(list(request.history.payload_list))
                json_history_timestamp = json.dumps(
                    list(request.history.timestamp_list)
                )
                self.conn.execute(
                    """INSERT INTO did_requests (request_id, response_id, did, json_history_payload, json_history_timestamp, interval_current, exec_time)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        request.ids.request_id,
                        request.ids.response_id,
                        request.ids.did,
                        json_history_payload,
                        json_history_timestamp,
                        request.interval._current,
                        request.exec_time,
                    ),
                )

    def load_list(self, want_payload_history: bool):
        """
        Retrieves a list of `DidRequest` objects from the database.

        :param want_payload_history: Whether to include payload history in the loaded objects.
        :type want_payload_history: bool
        :return: A list of `DidRequest` objects retrieved from the database.
        :rtype: list
        """
        with self.conn:
            # Check if the did_requests table exists in the database
            cursor = self.conn.execute(f"PRAGMA table_info(did_requests)")

            # iterate over the rows in the cursor and check if the column name matches "json_history_payload"
            column_names = [row[1] for row in cursor]
            if "json_history_payload" in column_names:
                # print("The json_history_payload column exists in the table.")
                has_json_history_payload = True
            else:
                # print("The json_history_payload column does not exist in the table.")
                has_json_history_payload = False

            if "json_history_timestamp" in column_names:
                # print("The json_history_timestamp column exists in the table.")
                has_json_history_timestamp = True
            else:
                # print("The json_history_timestamp column does not exist in the table.")
                has_json_history_timestamp = False

            if "interval_current" in column_names:
                # print("The interval_current column exists in the table.")
                has_interval = True
            else:
                # print("The interval_current column does not exist in the table.")
                has_interval = False

            if (
                has_interval
                and has_json_history_payload
                and has_json_history_timestamp
                and want_payload_history
            ):
                cursor = self.conn.execute(
                    "SELECT request_id, response_id, did, json_history_payload, json_history_timestamp, interval_current, exec_time FROM did_requests"
                )
                did_requests = []
                for row in cursor:
                    request = DidRequest(*row[:3])
                    request.history.payload_list = json.loads(row[3])
                    request.history.timestamp_list = json.loads(row[4])
                    request.interval._current = row[5]
                    request.exec_time = row[6]
                    did_requests.append(request)
            elif has_interval and has_json_history_payload and want_payload_history:
                cursor = self.conn.execute(
                    "SELECT request_id, response_id, did, json_history_payload, interval_current, exec_time FROM did_requests"
                )
                did_requests = []
                for row in cursor:
                    request = DidRequest(*row[:3])
                    request.history.payload_list = json.loads(row[3])
                    request.interval._current = row[4]
                    request.exec_time = row[5]
                    did_requests.append(request)
            elif has_json_history_payload and want_payload_history:
                cursor = self.conn.execute(
                    "SELECT request_id, response_id, did, json_history_payload FROM did_requests"
                )
                did_requests = []
                for row in cursor:
                    request = DidRequest(*row[:3])
                    request.history.payload_list = json.loads(row[3])
                    did_requests.append(request)
            else:
                cursor = self.conn.execute(
                    "SELECT request_id, response_id, did FROM did_requests"
                )
                did_requests = []
                for row in cursor:
                    request = DidRequest(*row[:3])
                    did_requests.append(request)

            return did_requests

    def export_db_as_csv(self):
        """
        Export the entire database as CSV files, with each table as a separate file.
        """
        # Extract the base filename without the extension
        base_name = os.path.splitext(self.db_file)[0]

        # Create a cursor object to execute SQL queries
        cursor = self.conn.cursor()

        # Get the list of table names in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        # Export each table as a separate CSV file
        for table in tables:
            table_name = table[0]
            csv_file = f"{base_name}_database.csv"

            # Execute a query to retrieve all rows and column names from the table
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()

            cursor.execute(f"SELECT * FROM {table_name};")
            rows = cursor.fetchall()

            # Write the rows to the CSV file
            with open(csv_file, "w", newline="") as file:
                writer = csv.writer(file)

                # Write column names as the first row
                writer.writerow([column[1] for column in columns])

                # Write data rows
                writer.writerows(rows)

            print(f"Table '{table_name}' exported to '{csv_file}'.")

        # Close the database connection
        self.conn.close()

    def delete_duplicates(self):
        """
        Delete duplicate entries from the database.
        """
        filtered_did_requests = []
        unique_ids = []
        did_requests = self.load_list(True)
        for request in did_requests:
            if request.make_unique_ID() not in unique_ids:
                filtered_did_requests.append(request)
                unique_ids.append(request.make_unique_ID())

        self.reset_database()
        self.store_list(filtered_did_requests)
        print(
            f"CAN ID {hex(filtered_did_requests[0].ids.request_id)}: Deleted {len(unique_ids) - len(did_requests)} duplicates."
        )

    def export_db_as_csv_single_list(self):
        """
        Export the entire database as CSV files, with each table as a separate file.
        """
        # Extract the folder of the db file
        base_name = os.path.split(self.db_file)[0]
        vehicle_name = os.path.split(base_name)[1]

        # Create a cursor object to execute SQL queries
        cursor = self.conn.cursor()

        # Get the list of table names in the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        csv_file = os.path.join(base_name, f"{vehicle_name}_database.csv")

        # Export each table as a separate CSV file
        for table in tables:
            table_name = table[0]

            # Execute a query to retrieve all rows and column names from the table
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()

            cursor.execute(f"SELECT * FROM {table_name};")
            rows = cursor.fetchall()

            # Write the rows to the CSV file
            with open(csv_file, "a", newline="") as file:
                writer = csv.writer(file)

                if file is not None:
                    # Write column names as the first row
                    writer.writerow([column[1] for column in columns])

                # Write data rows
                writer.writerows(rows)

        print(f"Table '{table_name}' exported to '{csv_file}'.")

        # Close the database connection
        self.conn.close()
