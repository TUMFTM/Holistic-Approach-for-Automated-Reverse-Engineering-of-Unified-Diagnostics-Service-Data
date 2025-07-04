"""
This module defines classes for discovering UDS servers and corresponding Data IDs.

Classes:
    - ArbitrationIDPair: A utility class representing a pair of arbitration IDs.
    - Discoverer: A class for discovering UDS (Unified Diagnostic Service) servers and Data IDs.
"""

from revcan.signal_discovery.dids import DidRequest
from revcan.signal_discovery.utils.iso14229_1 import Iso14229_1, Services
from revcan.signal_discovery.utils.iso15765_2 import IsoTp
from revcan.signal_discovery.utils.can_actions import CanActions, auto_blacklist
from revcan.signal_discovery.utils.constants import (
    ARBITRATION_ID_MAX,
    ARBITRATION_ID_MAX_EXTENDED,
)
from revcan.signal_discovery.utils.constants import ARBITRATION_ID_MIN
from can.thread_safe_bus import ThreadSafeBus
from can.message import Message
from can.notifier import Notifier
from can.listener import Listener, BufferedReader
from sys import stdout

import os
import csv
import threading
import time


class ArbitrationIDPair:
    """
    A class representing a pair of arbitration IDs.

    Attributes:
        request_id (int): The arbitration ID for requests.
        response_id (int): The arbitration ID for responses.

    Methods:
        __init__(self, request_id, response_id): Initializes a new ArbIdPair instance.
        __str__(self): Returns a string representation of the ArbIdPair.
    """

    def __init__(self, request_id, response_id) -> None:
        """
        Initializes a new ArbitrationIDPair instance.

        Parameters:
        - request_id (int): The arbitration ID for requests.
        - response_id (int): The arbitration ID for responses.
        """

        self.request_id = request_id
        self.response_id = response_id

    def __str__(self) -> str:
        """
        Returns a string representation of the ArbitrationIDPair.

        Returns:
        - str: A string containing the formatted request and response IDs.
        """
        return (
            f"Request ID: {hex(self.request_id)}, Response ID: {hex(self.response_id)}"
        )


class Discoverer:
    """
    A class for discovering UDS (Unified Diagnostic Service) servers and Data IDs.

    Constants:
        DELAY_DISCOVERY (float): Delay for UDS server discovery.
        DELAY_TESTER_PRESENT (float): Delay for UDS tester present operation.
        DELAY_SECSEED_RESET (float): Delay for UDS security seed reset operation.
        TIMEOUT_SERVICES (float): Timeout for UDS services.
        VERIFICATION_BACKTRACK (int): Max number of arbitration IDs to backtrack during verification.
        VERIFICATION_EXTRA_DELAY (float): Extra time to wait for responses during verification.
        BYTE_MIN (int): Minimum byte value.
        BYTE_MAX (int): Maximum byte value.
        DUMP_DID_MIN (int): Minimum Device Identifier (DID) value for dumping.
        DUMP_DID_MAX (int): Maximum Device Identifier (DID) value for dumping.
        DUMP_DID_TIMEOUT (float): Timeout for dumping DIDs.

    Attributes:
        found_arbitration_IDs: List of ArbitrationIDPair objects representing found arbitration ID pairs.
        found_requests: List of DidRequest objects representing found requests.
        received_messages_buffer: Buffer for received messages.
        rx_thread: Thread for receiving messages.
        evaluate_buffer_thread: Thread for evaluating received messages buffer.
        valid_session_control_responses: Valid session control responses.

    Methods:
        __init__(self): Initializes a new Discoverer object.
        __str__(self): Returns a string representation of the Discoverer instance.
        connect_bus(self): Connects to the CAN bus using the specified interface and channel.
        send_message(self, arbitration_id, data, force_extended=False): Sends a CAN message with the given arbitration ID and data.
        is_valid_response(self, message): Checks if the received CAN message is a valid response.
        get_did_from_response(self, response): Extracts the DID (Diagnostic Identifier) from a CAN response.
        is_first_frame(self, frame): Checks if a CAN frame is the first frame of a multi-frame message.
        receive_messages(self): Continuously receives CAN messages and adds them to the received messages buffer.
        evaluate_received_messages_buffer(self): Processes messages from the received messages buffer.
        discover_can_ids(self): Sends CAN messages to discover valid arbitration IDs.
        dids_from_range(self, min_did=0x0, max_did=0xFFFF): Generates a list of DIDs (Diagnostic Identifiers) within the specified range.
        save_csv_arbitration_ids(self, save_csv_file): Saves the found arbitration ID pairs to a CSV file.
        read_csv_arbitration_ids(self, save_csv_file): Reads arbitration ID pairs from a CSV file.
        read_csv_arbitration_ids_no_duplicates(self, save_csv_file): Reads arbitration ID pairs from a CSV file, removing duplicate entries.
        uds_discover_servers_initial(self, min_id=None, max_id=None): Initiates the UDS (Unified Diagnostic Service) server discovery.
        uds_discovery(self, min_id=None, max_id=None, blacklist_args=None, auto_blacklist_duration=None, delay=DELAY_DISCOVERY, verify=True, print_results=True):
            Scans for diagnostics support by brute forcing session control messages to different arbitration IDs.
        discover_all_dids(self): Discovers all DIDs (Data Identifiers) for the found arbitration ID pairs.
        uds_discover_dids(self, arb_id_request, arb_id_response, timeout=None, min_did=DUMP_DID_MIN, max_did=DUMP_DID_MAX, print_results=True, print_debug=False, max_execution_time=2, max_failures=10):
            Sends read data by identifier (DID) messages to 'arb_id_request'.
        add_missing_request_ids_from_broadcaster(self): Adds missing request IDs by performing UDS discovery based on the found broadcaster IDs.
        delete_duplicate_broadcast_ids(self): Deletes duplicate broadcaster IDs from the found arbitration ID pairs.
        find_broadcaster(self): Finds broadcaster IDs from the found arbitration ID pairs.
        find_duplicates(self, lst): Finds duplicate elements in a list.
    """

    # The following parameters were copied from uds.py in the Caring Caribou project.
    # [
    DELAY_DISCOVERY = 0.025
    DELAY_TESTER_PRESENT = 0.5
    DELAY_SECSEED_RESET = 0.01
    TIMEOUT_SERVICES = 0.2

    # Max number of arbitration IDs to backtrack during verification
    VERIFICATION_BACKTRACK = 5
    # Extra time in seconds to wait for responses during verification
    VERIFICATION_EXTRA_DELAY = 0.5

    BYTE_MIN = 0x00
    BYTE_MAX = 0xFF

    DUMP_DID_MIN = 0x0000
    DUMP_DID_MAX = 0xFFFF
    DUMP_DID_TIMEOUT = 0.2
    # ]

    found_arbitration_IDs: list[ArbitrationIDPair]
    found_requests: list[DidRequest]

    def __init__(self) -> None:
        """
        Initializes a new Discoverer object.

        Attributes:
        - found_arbitration_IDs: List of ArbitrationIDPair objects representing found arbitration ID pairs.
        - found_requests: List of DidRequest objects representing found requests.

        The object also initializes threads for receiving and evaluating messages.
        """

        self.found_arbitration_IDs = []
        self.found_requests = []
        self.received_messages_buffer = []
        self.rx_thread = threading.Thread(target=self.receive_messages)
        self.rx_thread.daemon = True
        self.evaluate_buffer_thread = threading.Thread(
            target=self.evaluate_received_messages_buffer
        )
        self.evaluate_buffer_thread.daemon = True
        self.valid_session_control_responses = [0x50, 0x7F]

    def __str__(self) -> str:
        pass

    def connect_bus(self):
        """
        Connects to the CAN bus using the specified interface and channel.
        """

        self.bus = ThreadSafeBus(interface="socketcan", channel="can0")

    def send_message(self, arbitration_id, data, force_extended=False):
        """
        Sends a CAN message with the given arbitration ID and data.

        Parameters:
        - arbitration_id: The arbitration ID of the CAN message.
        - data: The data to be sent in the CAN message.
        - force_extended: If True, the message will be sent as an extended frame.

        Note: The method constructs a Message object and sends it to the bus.
        """

        is_extended = force_extended or arbitration_id > ARBITRATION_ID_MAX
        msg = Message(
            arbitration_id=arbitration_id, is_extended_id=is_extended, data=data
        )
        self.bus.send(msg)

    def is_valid_response(self, message):
        """
        Checks if the received CAN message is a valid response.

        Parameters:
        - message: The received CAN message.

        Returns:
        - True if the message is a valid response, False otherwise.
        """

        return (
            len(message.data) >= 3
            and message.data[1] in self.valid_session_control_responses
        )

    def get_did_from_response(self, response):
        """
        Extracts the DID (Diagnostic Identifier) from a CAN response.

        Parameters:
        - response: The response message.

        Returns:
        - The extracted DID or None if the conditions are not met.
        """

        # Check if the list has at least 4 elements
        if len(response) >= 3:
            # Check if the first element is 0x03 and the second is 0x62
            if response[0] == 0x62:
                # Concatenate the third and fourth elements and convert to an integer
                concatenated_int = (response[1] << 8) | response[2]
                return concatenated_int
        return None  # Return None if the conditions are not met or if the list is too short

    def is_first_frame(self, frame):
        """
        Checks if a CAN frame is the first frame of a multi-frame message.

        Parameters:
        - frame: The CAN frame.

        Returns:
        - True if the frame is a first frame, False otherwise.
        """

        # Check if the frame is a multi-frame message
        if (frame[0] & 0xF0) == 0x10:
            # Check if the frame is a first frame
            if (frame[0] & 0x0F) > 0:
                return False
            else:
                return True
        else:
            return False

    def receive_messages(self):
        """
        Continuously receives CAN messages and adds them to the received messages buffer.
        """

        while True:
            received_message = IsoTp.indication()
            print(
                f"Received message with ID {hex(received_message.arbitration_id)} and data {received_message.data}"
            )
            self.received_messages_buffer.append(received_message)

    def evaluate_received_messages_buffer(self):
        """
        Processes messages from the received messages buffer.
        """

        while len(self.received_messages_buffer) > 0:
            received_message = self.received_messages_buffer.pop(0)
            print(
                f"Read message from buffer with ID {hex(received_message.arbitration_id)} and data {received_message.data}"
            )

    def discover_canids(self):
        """
        Sends CAN messages to discover valid arbitration IDs.
        """

        msg_data = bytearray([0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
        for can_id in range(0x7FF + 1):
            self.send_message(can_id, msg_data)
            time.sleep(0.025)

    def dids_from_range(self, min_did=0x0, max_did=0xFFFF):
        """
        Generates a list of DIDs (Diagnostic Identifiers) within the specified range.

        Parameters:
        - min_did: The minimum DID value.
        - max_did: The maximum DID value.

        Returns:
        - A list of DIDs.
        """

        num_dids = [*range(min_did, max_did + 1, 1)]
        dids = []
        for did in num_dids:
            dids.append(did)
        return dids

    def save_csv_arbitration_IDs(self, save_csv_file):
        """
        Saves the found arbitration ID pairs to a CSV file.

        Parameters:
        - save_csv_file: The path to the CSV file.
        """

        # Open a csv file to write the found arbitration ID pairs to
        with open(save_csv_file, "w", newline = '') as found_arb_id_pair_csv_file:
            # create the csv writer
            writer = csv.writer(found_arb_id_pair_csv_file)
            for arb_id_pair in self.found_arbitration_IDs:
                row = [hex(arb_id_pair.request_id), hex(arb_id_pair.response_id)]
                # write a row to the csv file
                writer.writerow(row)

    def read_csv_arbitration_IDs(self, save_csv_file):
        """
        Reads arbitration ID pairs from a CSV file.

        Parameters:
        - save_csv_file: The path to the CSV file.
        """

        with open(save_csv_file, "r") as found_arb_id_pair_csv_file:
            csv_reader = csv.reader(found_arb_id_pair_csv_file)
            for line in csv_reader:
                id_pair = ArbitrationIDPair(int(line[0], 16), int(line[1], 16))
                self.found_arbitration_IDs.append(id_pair)

    def read_csv_arbitration_IDs_no_duplicates(self, save_csv_file):
        """
        Reads arbitration ID pairs from a CSV file, removing duplicate entries.

        Parameters:
        - save_csv_file: The path to the CSV file.
        """

        with open(save_csv_file, "r") as found_arb_id_pair_csv_file:
            csv_reader = csv.reader(found_arb_id_pair_csv_file)
            lines = []
            for line in csv_reader:
                if line not in lines:
                    lines.append(line)
            for line in lines:
                id_pair = ArbitrationIDPair(int(line[0], 16), int(line[1], 16))
                self.found_arbitration_IDs.append(id_pair)

    def uds_discover_servers_initial(self, min_id=None, max_id=None):
        """
        Initiates the UDS (Unified Diagnostic Service) server discovery.

        Parameters:
        - min_id: The minimum arbitration ID value.
        - max_id: The maximum arbitration ID value.
        """

        self.found_arbitration_IDs = self.uds_discovery(min_id, max_id)

    # The following method was copied from uds.py in the Caring Caribou project and modified to work in this context
    def uds_discovery(
        self,
        min_id=None,
        max_id=None,
        blacklist_args=None,
        auto_blacklist_duration=None,
        delay=DELAY_DISCOVERY,
        verify=True,
        print_results=True,
    ):
        """
        Scans for diagnostics support by brute forcing session control
        messages to different arbitration IDs.

        Returns a list of all (client_arb_id, server_arb_id) pairs found.

        Parameters:
        - min_id: Start arbitration ID value.
        - max_id: End arbitration ID value.
        - blacklist_args: Blacklist for arbitration ID values.
        - auto_blacklist_duration: Seconds to scan for interfering arbitration IDs to blacklist automatically.
        - delay: Delay between each message.
        - verify: Whether found arbitration IDs should be verified.
        - print_results: Whether results should be printed to stdout.
        """
        # Set defaults
        if min_id is None:
            min_id = ARBITRATION_ID_MIN
        if max_id is None:
            if min_id <= ARBITRATION_ID_MAX:
                max_id = ARBITRATION_ID_MAX
            else:
                # If min_id is extended, use an extended default max_id as well
                max_id = ARBITRATION_ID_MAX_EXTENDED
        if auto_blacklist_duration is None:
            auto_blacklist_duration = 0
        if blacklist_args is None:
            blacklist_args = []

        # Sanity checks
        if max_id < min_id:
            raise ValueError(
                "max_id must not be smaller than min_id -"
                " got min:0x{0:x}, max:0x{1:x}".format(min_id, max_id)
            )
        if auto_blacklist_duration < 0:
            raise ValueError(
                "auto_blacklist_duration must not be smaller "
                "than 0, got {0}'".format(auto_blacklist_duration)
            )

        diagnostic_session_control = Services.DiagnosticSessionControl
        service_id = diagnostic_session_control.service_id
        sub_function = diagnostic_session_control.DiagnosticSessionType.DEFAULT_SESSION
        session_control_data = [service_id, sub_function]

        found_arbitration_IDs = []

        with IsoTp(None, None) as tp:
            # Perform automatic blacklist scan
            if auto_blacklist_duration > 0:
                auto_bl_arb_ids = auto_blacklist(
                    tp.bus,
                    auto_blacklist_duration,
                    self.is_valid_response,
                    print_results,
                )
                blacklist |= auto_bl_arb_ids

            # Prepare session control frame
            sess_ctrl_frm = tp.get_frames_from_message(session_control_data)
            send_arb_id = min_id - 1
            while send_arb_id < max_id:
                send_arb_id += 1
                blacklist = []
                if print_results:
                    print(
                        "\rSending Diagnostic Session Control to 0x{0:04x}".format(
                            send_arb_id
                        ),
                        end="\n",
                    )
                    stdout.flush()
                # Send Diagnostic Session Control only if there are no messages received for the duration of delay
                end_time = time.time() + delay

                while time.time() < end_time:
                    received_message = tp.bus.recv(0)
                    if received_message is None:
                        # No response received
                        continue
                    if self.is_valid_response(received_message):
                        end_time = time.time() + delay

                # Send Diagnostic Session Control
                tp.transmit(sess_ctrl_frm, send_arb_id, None)
                end_time = time.time() + delay
                # Listen for response
                received_messages = []
                while time.time() < end_time:
                    received_message = tp.bus.recv(0)
                    if received_message is None:
                        # No response received
                        continue
                    if received_message.arbitration_id in blacklist:
                        # Ignore blacklisted arbitration IDs
                        continue
                    if self.is_valid_response(received_message):
                        received_messages.append(received_message)
                if print_results:
                    if len(received_messages) > 1:
                        print("Received multiple messages:\n")
                        for message in received_messages:
                            print(hex(message.arbitration_id))
                    elif len(received_messages) == 1:
                        print("Received single message")
                for msg in received_messages:
                    if msg is None:
                        # No response received
                        continue
                    if msg.arbitration_id in blacklist:
                        # Ignore blacklisted arbitration IDs
                        continue
                    if self.is_valid_response(msg):
                        # Valid response
                        if verify:
                            # Verification - backtrack the latest IDs and
                            # verify that the same response is received
                            verified = False
                            # Set filter to only receive messages for the
                            # arbitration ID being verified
                            tp.set_filter_single_arbitration_id(msg.arbitration_id)
                            if print_results:
                                print(
                                    "\n  Verifying potential response from "
                                    "0x{0:04x}".format(send_arb_id)
                                )
                            verify_id_range = range(
                                send_arb_id,
                                send_arb_id - self.VERIFICATION_BACKTRACK,
                                -1,
                            )
                            for verify_arb_id in verify_id_range:
                                if print_results:
                                    print(
                                        "    Resending 0x{0:0x}... ".format(
                                            verify_arb_id
                                        ),
                                        end=" ",
                                    )
                                tp.transmit(sess_ctrl_frm, verify_arb_id, None)
                                # Give some extra time for verification, in
                                # case of slow responses
                                verification_end_time = (
                                    time.time() + delay + self.VERIFICATION_EXTRA_DELAY
                                )
                                while time.time() < verification_end_time:
                                    verification_msg = tp.bus.recv(0)
                                    if verification_msg is None:
                                        continue
                                    if self.is_valid_response(verification_msg):
                                        # Verified
                                        verified = True
                                        # Update send ID - if server responds
                                        # slowly, initial value may be faulty.
                                        # Also ensures we resume searching on
                                        # the next arb ID after the actual
                                        # match, rather than the one after the
                                        # last potential match (which could lead
                                        # to false negatives if multiple servers
                                        # listen to adjacent arbitration IDs and
                                        # respond slowly)
                                        send_arb_id = verify_arb_id
                                        break
                                if print_results:
                                    # Print result
                                    if verified:
                                        print("Success")
                                    else:
                                        print("No response")
                                if verified:
                                    # Verification succeeded - stop checking
                                    break
                            # Remove filter after verification
                            tp.clear_filters()
                            if not verified:
                                # Verification failed - move on
                                if print_results:
                                    print("  False match - skipping")
                                continue
                        if print_results:
                            if not verify:
                                # Blank line needed
                                print()
                            print(
                                "Found diagnostics server "
                                "listening at 0x{0:04x}, "
                                "response at 0x{1:04x}".format(
                                    send_arb_id, msg.arbitration_id
                                )
                            )
                        # Add found arbitration ID pair
                        found_arb_id_pair = ArbitrationIDPair(
                            send_arb_id, msg.arbitration_id
                        )
                        blacklist.append(msg.arbitration_id)
                        found_arbitration_IDs.append(found_arb_id_pair)
            if print_results:
                print()
        return found_arbitration_IDs

    def discover_all_dids(self):
        """
        Discovers all DIDs (Data Identifiers) for the found arbitration ID pairs.

        Returns:
        - list[DidRequest]: A list of DidRequest objects representing the discovered DIDs.
        """

        request_list = []
        for arb_pair in self.found_arbitration_IDs:
            responses = self.uds_discover_dids(
                arb_pair.request_id, arb_pair.response_id
            )
            for response in responses:
                if len(response) > 8:
                    pass
                request_list.append(
                    DidRequest(arb_pair.request_id, arb_pair.response_id, response)
                )
        return request_list

    # The following method was copied from uds.py in the Caring Caribou project and modified to work in this context
    def uds_discover_dids(
        self,
        arb_id_request,
        arb_id_response,
        timeout=None,
        min_did=DUMP_DID_MIN,
        max_did=DUMP_DID_MAX,
        print_results=True,
        print_debug=False,
        max_execution_time=2,
        max_failures=10,
        blacklist_IDs=None,
    ):
        """
        Sends read data by identifier (DID) messages to 'arb_id_request'.
        Returns a list of positive responses received from 'arb_id_response' within
        'timeout' seconds or an empty list if no positive responses were received.

        Parameters:
        - arb_id_request (int): The arbitration ID for requests.
        - arb_id_response (int): The arbitration ID for responses.
        - timeout (float, optional): Seconds to wait for a response before timing out, or None
                                    for the default UDS timeout.
        - min_did (int, optional): The minimum data identifier to read.
        - max_did (int, optional): The maximum data identifier to read.
        - print_results (bool): Whether to print results to stdout. Default is True.
        - print_debug (bool, optional): Whether to print debug information. Default is False.
        - max_execution_time (float, optional): Maximum allowed execution time for each DID. Default is 2 seconds.
        - max_failures (int, optional): Maximum allowed consecutive failures before returning False. Default is 10.

        Returns:
        - List[DidRequest] or False: A list of DidRequest objects containing the discovered DIDs and responses on success,
                                    or False if the maximum timeout failures are exceeded.
        """
        # Sanity checks
        if isinstance(timeout, float) and timeout < 0.0:
            raise ValueError("Timeout value ({0}) cannot be negative".format(timeout))

        if max_did < min_did:
            raise ValueError(
                "max_did must not be smaller than min_did -"
                " got min:0x{0:x}, max:0x{1:x}".format(min_did, max_did)
            )

        request_list = []
        failures = 0
        with IsoTp(
            arb_id_request=arb_id_request,
            arb_id_response=arb_id_response,
            blacklist_IDs=blacklist_IDs,
        ) as tp:
            # Setup filter for incoming messages
            # tp.set_filter_single_arbitration_id(arb_id_response)
            with Iso14229_1(tp) as uds:
                # Set timeout
                if timeout is not None:
                    uds.P3_CLIENT = timeout

                for identifier in range(min_did, max_did + 1):
                    # Track execution time for each read_data_by_identifier call
                    start_time = time.time()
                    response = uds.read_data_by_identifier(identifier=[identifier])
                    execution_time = time.time() - start_time

                    # Check if the execution time exceeds the maximum allowed time
                    if (
                        max_execution_time is not None
                        and execution_time > max_execution_time
                    ):
                        failures += 1
                        if failures >= max_failures:
                            if print_debug:
                                print(
                                    "Execution time for identifier {0}: {1:.3f}s, exceeded maximum time {2}s. Returning False.".format(
                                        identifier, execution_time, max_execution_time
                                    )
                                )
                            return False
                    # Only keep positive responses
                    if response and Iso14229_1.is_positive_response(response):
                        response_did = self.get_did_from_response(response)
                        if response_did is not None:
                            print("Success")
                            request_object = DidRequest(
                                arb_id_request, arb_id_response, response_did
                            )
                            request_object.history.payload_list.append(response)
                            request_list.append(request_object)

                            if print_results and response_did is not None:
                                print(
                                    hex(response_did),
                                    list(map(hex, response)),
                                )
                if print_results:
                    print("\nDone!")
                return request_list

    def add_missing_request_IDs_from_broadcaster(self):
        """
        Adds missing request IDs by performing UDS discovery based on the found broadcaster IDs.
        """

        broadcaster_list = self.find_broadcaster()
        if broadcaster_list is None:
            print("No broadcaster identified")
        else:
            iteration = 0
            current_found_arbitration_IDs = []
            for id in self.found_arbitration_IDs:
                current_found_arbitration_IDs.append(id)
            for broadcaster in broadcaster_list:
                for arb_id_pair in current_found_arbitration_IDs:
                    if arb_id_pair.request_id == broadcaster:
                        potential_new_pair = None
                        if arb_id_pair.response_id <= ARBITRATION_ID_MAX:
                            potential_new_pair = ArbitrationIDPair(
                                arb_id_pair.response_id - 0x6A, arb_id_pair.response_id
                            )
                        else:
                            potential_new_pair = ArbitrationIDPair(
                                arb_id_pair.response_id - 0x20000,
                                arb_id_pair.response_id,
                            )
                        if potential_new_pair:
                            iteration += 1
                            new_pairs = self.uds_discovery(
                                min_id=potential_new_pair.request_id - 0xF,
                                max_id=potential_new_pair.request_id + 0xF,
                                print_results=False,
                            )
                            print(f"Finished discovery {iteration}")
                        for new_pair in new_pairs:
                            self.found_arbitration_IDs.append(new_pair)

    def delete_duplicate_broadcast_IDs(self):
        """
        Deletes duplicate broadcaster IDs from the found arbitration ID pairs.
        """

        broadcaster_list = self.find_broadcaster()
        if broadcaster_list is None:
            print("No broadcaster identified")
        else:
            current_arbitration_ids = []
            for id in self.found_arbitration_IDs:
                current_arbitration_ids.append(id)

            # sort the list by response_id
            self.found_arbitration_IDs = sorted(
                current_arbitration_ids, key=lambda pair: pair.response_id
            )
            # print the sorted list
            for pair in self.found_arbitration_IDs:
                print(pair)

    def find_broadcaster(self):
        """
        Finds broadcaster IDs from the found arbitration ID pairs.

        Returns:
        - set[int] or None: A set of broadcaster IDs if found, or None if no broadcaster IDs are identified.
        """

        request_IDs = []
        for arb_id_pair in self.found_arbitration_IDs:
            request_IDs.append(arb_id_pair.request_id)
        broadcaster_list = self.find_duplicates(request_IDs)
        return broadcaster_list

    def find_duplicates(self, lst):
        """
        Finds duplicate elements in a list.

        Parameters:
        - lst (list): The list to search for duplicates.

        Returns:
        - set: A set of duplicate elements found in the list.
        """

        seen = {}
        duplicates = []
        for elem in lst:
            if elem in seen:
                duplicates.append(elem)
            else:
                seen[elem] = True
        return set(duplicates)
    
    def delete_duplicates_and_broadcasters_and_sort(self, original_can_ids_path: str):

        original_can_ids_found = []
        with open(original_can_ids_path, "r") as found_arb_id_pair_csv_file:
            csv_reader = csv.reader(found_arb_id_pair_csv_file)
            for line in csv_reader:
                id_pair = ArbitrationIDPair(int(line[0], 16), int(line[1], 16))
                original_can_ids_found.append(id_pair)
        
        request_IDs = []
        for arb_id_pair in original_can_ids_found:
            request_IDs.append(arb_id_pair.request_id)
        broadcaster_list = self.find_duplicates(request_IDs)
        print(broadcaster_list)
        
        cleaned_ids_list = []
        unique_id_list = []
        for pair in self.found_arbitration_IDs:
            if pair.request_id not in broadcaster_list:
                unique_id = str(pair.request_id)+str(pair.response_id)
                if unique_id not in unique_id_list:
                    cleaned_ids_list.append(pair)
                    unique_id_list.append(unique_id)
                

        self.found_arbitration_IDs = cleaned_ids_list
        self.delete_duplicate_broadcast_IDs()