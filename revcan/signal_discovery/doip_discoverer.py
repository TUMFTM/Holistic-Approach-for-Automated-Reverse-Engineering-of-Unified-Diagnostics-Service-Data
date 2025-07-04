"""
This module defines classes for discovering UDS servers and corresponding Data IDs using the DOIP Protocoll.
It is copied from the CaringCaribou project and modified to work with the revcan project.
"""

from __future__ import print_function
import csv
import datetime
import time
import sys, os
import struct
from os.path import abspath, join, dirname
from collections import defaultdict

utils_path = abspath(join(dirname(__file__), "signal_discovery"))
sys.path.insert(0, utils_path)

from utils.common import list_to_hex_str, parse_int_dec_or_hex
from utils.constants import (
    ARBITRATION_ID_MAX,
    ARBITRATION_ID_MAX_EXTENDED,
)
from utils.constants import ARBITRATION_ID_MIN
from utils.iso14229_1 import Constants, NegativeResponseCodes
from utils.doipclient import DoIPClient
from utils.doipclient.connectors import DoIPClientUDSConnector
from utils.udsoncan.client import Client
from utils.udsoncan.exceptions import *
from utils.udsoncan.services import *
from utils.udsoncan.ResponseCode import ResponseCode
from utils.time_handling import TimeHandler
from revcan.signal_discovery.doip_dids import (
    DoIPDidRequest,
    DidRequestDatabase,
    DoIPConnector,
)
from revcan.signal_discovery.utils.network_actions import NetworkActions


class DOIP_Discoverer:
    def __init__(
        self,
        ecu_ip_address="255.255.255.255",
        connection_method="automatic",
        network_adapter="en6",
    ):
        self.ip = ecu_ip_address
        if connection_method == "entity":
            self.ip, self.logical_address = self.connect_to_ecu_entity()

        elif connection_method == "announcement":
            self.ip, self.logical_address = self.connect_to_ecu_anouncement()

        elif connection_method == "automatic":
            self.con = NetworkActions(network_adapter)
            self.ip = self.con.ip_address
            self.logical_address = self.con.logical_address
            self.client_ip_address = self.con.ip_address_client

        elif connection_method == "no vehicle test":
            pass

    UDS_SERVICE_NAMES = {
        0x10: "DIAGNOSTIC_SESSION_CONTROL",
        0x11: "ECU_RESET",
        0x14: "CLEAR_DIAGNOSTIC_INFORMATION",
        0x19: "READ_DTC_INFORMATION",
        0x20: "RETURN_TO_NORMAL",
        0x22: "READ_DATA_BY_IDENTIFIER",
        0x23: "READ_MEMORY_BY_ADDRESS",
        0x24: "READ_SCALING_DATA_BY_IDENTIFIER",
        0x27: "SECURITY_ACCESS",
        0x28: "COMMUNICATION_CONTROL",
        0x2A: "READ_DATA_BY_PERIODIC_IDENTIFIER",
        0x2C: "DYNAMICALLY_DEFINE_DATA_IDENTIFIER",
        0x2D: "DEFINE_PID_BY_MEMORY_ADDRESS",
        0x2E: "WRITE_DATA_BY_IDENTIFIER",
        0x2F: "INPUT_OUTPUT_CONTROL_BY_IDENTIFIER",
        0x31: "ROUTINE_CONTROL",
        0x34: "REQUEST_DOWNLOAD",
        0x35: "REQUEST_UPLOAD",
        0x36: "TRANSFER_DATA",
        0x37: "REQUEST_TRANSFER_EXIT",
        0x38: "REQUEST_FILE_TRANSFER",
        0x3D: "WRITE_MEMORY_BY_ADDRESS",
        0x3E: "TESTER_PRESENT",
        0x7F: "NEGATIVE_RESPONSE",
        0x83: "ACCESS_TIMING_PARAMETER",
        0x84: "SECURED_DATA_TRANSMISSION",
        0x85: "CONTROL_DTC_SETTING",
        0x86: "RESPONSE_ON_EVENT",
        0x87: "LINK_CONTROL",
    }

    DELAY_DISCOVERY = 0.2
    DELAY_TESTER_PRESENT = 0.5
    DELAY_SECSEED_RESET = 0.01
    DELAY_FUZZ_RESET = 3.901
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

    # Diagnostic Message payload type - see Table 21 "Payload type diagnostic message structure"
    # https://python-doipclient.readthedocs.io/en/latest/messages.html
    PAYLOAD_TYPE = 0x8001

    class DevNull:
        # Supress errors solution:
        # https://stackoverflow.com/questions/5925918/python-suppressing-errors-from-going-to-commandline
        def write(self, msg):
            pass

    # Duplicate testing from https://www.iditect.com/guide/python/python_howto_find_the_duplicates_in_a_list.html
    def find_duplicates(self, sequence):
        first_seen = set()
        first_seen_add = first_seen.add
        duplicates = set(i for i in sequence if i in first_seen or first_seen_add(i))
        return duplicates

    def ecu_reset(self, client, reset_type):
        if reset_type == 1:
            client.ecu_reset(ECUReset.ResetType.hardReset)
        elif reset_type == 2:
            client.ecu_reset(ECUReset.ResetType.keyOffOnReset)
        elif reset_type == 3:
            client.ecu_reset(ECUReset.ResetType.softReset)
        elif reset_type == 4:
            client.ecu_reset(ECUReset.ResetType.enableRapidPowerShutDown)
        elif reset_type == 5:
            client.ecu_reset(ECUReset.ResetType.disableRapidPowerShutDown)

    def extended_session(self, client, session_type):
        if session_type == 1:
            client.change_session(DiagnosticSessionControl.Session.defaultSession)
        elif session_type == 2:
            client.change_session(DiagnosticSessionControl.Session.programmingSession)
        elif session_type == 3:
            client.change_session(
                DiagnosticSessionControl.Session.extendedDiagnosticSession
            )
        elif session_type == 4:
            client.change_session(
                DiagnosticSessionControl.Session.safetySystemDiagnosticSession
            )

    def connect_to_ecu_anouncement(self, timeout=5):
        print("Waiting for Vehicle Identification Announcement\n")
        print(
            "Power cycle your ECU and wait for a few seconds for the broadcast to be received\n"
        )
        try:
            address, announcement = DoIPClient.await_vehicle_announcement(
                timeout=timeout
            )
            logical_address = announcement.logical_address
            ip, port = address
            print(
                "ECU IP and port found: ",
                ip,
                ",",
                port,
                "\nECU Logical Address Found: ",
                hex(logical_address),
                "\n",
            )
            return ip, logical_address
        except TimeoutError:
            print("Connection timed out. Unable to connect to ECU.")
            return None, None

    def connect_to_ecu_entity(self, timeout=5):
        print("Waiting for Vehicle Identification Announcement\n")
        print(
            "Power cycle your ECU and wait for a few seconds for the broadcast to be received\n"
        )

        start_time = time.time()

        while True:
            elapsed_time = time.time() - start_time

            if elapsed_time >= timeout:
                print("Connection timed out. Unable to connect to ECU.")
                return None, None
            try:
                address, announcement = DoIPClient.get_entity(ecu_ip_address=self.ip)
                logical_address = announcement.logical_address
                ip, port = address
                print(
                    "ECU IP and port found: ",
                    ip,
                    ",",
                    port,
                    "\nECU Logical Address Found: ",
                    hex(logical_address),
                    "\n",
                )
                return ip, logical_address
            except Exception as e:
                # Handle other potential exceptions if needed
                print(f"An error occurred: {e}")

            time.sleep(0.5)  # to prevent spamming the ECU

    @classmethod
    def uds_discovery_initialiser(
        cls,
        file,
        network_adapter: str,
        min_id=0x0000,
        max_id=0xFFFF,
        blacklist=[],
        auto_blacklist_duration=None,
        delay=0.0,
        print_results=True,
        client_logical_address=None,
    ):
        # adds all the blacklisted addresses to the blacklist
        blacklist_final = []
        for i in blacklist:
            numbers = list(range(i[0], i[1]))
            for number in numbers:
                blacklist_final.append(number)

        # print("blacklist", blacklist_final)

        discoverer = DOIP_Discoverer(
            connection_method="automatic", network_adapter=network_adapter
        )

        try:
            servers = discoverer.uds_discovery(
                min_id,
                max_id,
                blacklist_final,
                auto_blacklist_duration,
                delay,
                print_results=print_results,
                client_logical_address=client_logical_address,
            )
            print(servers)
            if servers == []:
                # No UDS discovereds
                print("\nDiagnostics service could not be found.")
            else:
                discoverer.save_data_to_csv(csv_file=file, data=servers, type="Servers")
            return

        except ValueError as e:
            print("Discovery failed: {0}".format(e))
            return []

    def uds_discovery(
        self,
        min_id,
        max_id,
        blacklist_args,
        auto_blacklist_duration,
        delay,
        print_results=True,
        client_logical_address=None,
    ):
        """Scans for diagnostics support by brute forcing session control
            messages to different arbitration IDs.

        Returns a list of all (client_arb_id, server_arb_id) pairs found.

        :param min_id: start arbitration ID value
        :param max_id: end arbitration ID value
        :param blacklist_args: blacklist for arbitration ID values
        :param auto_blacklist_duration: seconds to scan for interfering
        arbitration IDs to blacklist automatically
        :param delay: delay between each message
        :param print_results: whether results should be printed to stdout
        :type min_id: int
        :type max_id: int
        :type blacklist_args: [int]
        :type auto_blacklist_duration: float
        :type delay: float
        :type print_results: bool
        :return: list of (client_arbitration_id, server_arbitration_id) pairs
        :rtype [(int, int)]
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
                "max_id must not be smaller than min_id - got min:0x{0:x}, max:0x{1:x}".format(
                    min_id, max_id
                )
            )
        if auto_blacklist_duration < 0:
            raise ValueError(
                "auto_blacklist_duration must not be smaller than 0, got {0}'".format(
                    auto_blacklist_duration
                )
            )
        elif auto_blacklist_duration > 0:
            timeout = auto_blacklist_duration
        else:
            timeout = 2

        blacklist = set(blacklist_args)

        found_servers = []

        server_id = min_id

        print("Searching for Client Node ID\n")

        if client_logical_address is None:
            self.client_logical_address = self.get_client_logical_address()
        else:
            self.client_logical_address = client_logical_address

        try:
            doip_client = DoIPClient(
                ecu_ip_address=self.ip,
                initial_ecu_logical_address=server_id,
                client_logical_address=self.client_logical_address,
                #client_ip_address=self.client_ip_address,
            )
            conn = DoIPClientUDSConnector(doip_client, timeout=timeout)
        except OSError as e:
            print(e)
            return

        while server_id < max_id:
            server_id += 1

            if server_id in blacklist:
                # Ignore blacklisted arbitration IDs
                continue

            if print_results:
                print(
                    "\rSending Diagnostic Session Control to 0x{0:04x}".format(
                        server_id
                    ),
                    end="",
                )
            try:
                with Client(
                    conn, request_timeout=timeout, ecu_logical_address=server_id
                ) as client:
                    response = client.change_session(
                        DiagnosticSessionControl.Session.defaultSession  # type: ignore
                    )

                if response == None:
                    continue
                elif response.positive:
                    print(
                        "\n\nFound diagnostics server "
                        "listening at 0x{0:04x}, "
                        "response at 0x{1:04x}".format(self.logical_address, server_id)
                    )
                    # # adds the found servers to the list;
                    # # the loop asures that only the ecu addresses are added and not the tester
                    # if client_id_status == 1:
                    found_servers.append(hex(server_id))

                else:
                    blacklist.add(server_id)

            except KeyboardInterrupt:
                return found_servers
            except ConnectionRefusedError:
                time.sleep(delay)

            except ConnectionResetError:
                time.sleep(delay)
                continue

            except TimeoutError:
                sys.stderr = self.DevNull()
                continue

            except OSError:
                print("Please check the connection and try again.\n")

        return found_servers

    def get_client_logical_address(self, min_id=0x0000, max_id=0xFFFF):
        client_id = min_id - 1
        while client_id < max_id:
            client_id += 1

            print(
                "Sending Diagnostic Session Control to 0x{0:04x}".format(client_id),
                end="",
            )
            try:
                doip_client = DoIPClient(
                    ecu_ip_address=self.ip,
                    initial_ecu_logical_address=self.logical_address,
                    client_logical_address=client_id,
                )

                con = DoIPClientUDSConnector(doip_client)
                with Client(con, request_timeout=0.2) as client:
                    response = client.change_session(
                        DiagnosticSessionControl.Session.extendedDiagnosticSession  # type: ignore
                    )
                    if response == None:
                        continue
                    elif response.positive:
                        return client_id
                    else:
                        continue
            except:
                continue

    def service_discovery(
        self,
        arb_id_request,
        arb_id_response,
        timeout,
        min_id=BYTE_MIN,
        max_id=BYTE_MAX,
        print_results=True,
    ):
        """Scans for supported UDS services on the specified arbitration ID.
        Returns a list of found service IDs.

        :param arb_id_request: arbitration ID for requests
        :param arb_id_response: arbitration ID for responses
        :param timeout: delay between each request sent
        :param min_id: first service ID to scan
        :param max_id: last service ID to scan
        :param print_results: whether progress should be printed to stdout
        :type arb_id_request: int
        :type arb_id_response: int
        :type timeout: float
        :type min_id: int
        :type max_id: int
        :type print_results: bool
        :return: list of supported service IDs
        :rtype [int]
        """
        found_services = []

        print("Discovering Services\n")

        try:
            for service_id in range(min_id, max_id + 1):
                if print_results:
                    print(
                        "\rProbing service 0x{0:02x} ({0}/{1}): found {2}".format(
                            service_id, max_id, len(found_services)
                        ),
                        end="",
                    )

                doip_client = DoIPClient(
                    self.ip,
                    self.logical_address,
                    client_logical_address=arb_id_response,
                )

                conn = DoIPClientUDSConnector(doip_client)

                s = struct.pack("<h", service_id)

                doip_message = (
                    struct.pack("!HH", arb_id_response, arb_id_request)
                    + s[:1]
                    + b"\x00"
                )

                try:
                    with Client(conn, request_timeout=timeout) as client:
                        self.extended_session(client, session_type=3)

                        doip_client.send_doip(self.PAYLOAD_TYPE, doip_message)
                        response = doip_client.receive_diagnostic(timeout)

                        doip_client.close()

                        if (
                            response is None
                            or response[2]
                            == NegativeResponseCodes.SERVICE_NOT_SUPPORTED
                        ):
                            continue

                        if (
                            response[2]
                            == NegativeResponseCodes.SUB_FUNCTION_NOT_SUPPORTED
                            or response[2]
                            == NegativeResponseCodes.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT
                        ):
                            response_id = service_id
                            response_service_id = response[2]
                            status = response[2]
                            if response_id != Constants.NR_SI:
                                request_id = service_id
                                found_services.append(request_id)
                            elif status != NegativeResponseCodes.SERVICE_NOT_SUPPORTED:
                                # Any other response than "service not supported" counts
                                found_services.append(response_service_id)

                except ConfigError:
                    sys.stderr = self.DevNull()
                    time.sleep(3)
                    continue
                except OSError:
                    sys.stderr = self.DevNull()
                    time.sleep(3)
                    continue
                except IndexError:
                    sys.stderr = self.DevNull()
                    continue

            if print_results:
                print("\nDone!")

        except KeyboardInterrupt:
            if print_results:
                print("\nInterrupted by user!\n")
            return found_services

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError, OSError):
            print("Please check the connection and try again.\n")

        return found_services

    @classmethod
    def service_discovery_initialiser(
        cls,
        arb_id_request: int,
        arb_id_response: int,
        interface=str,
        timeout=5,
        print_results=True,
    ):
        """Wrapper used to initiate a service discovery scan"""

        discoverer = DOIP_Discoverer(
            network_adapter=interface, connection_method="automatic"
        )

        # Probe services
        found_services = discoverer.service_discovery(
            arb_id_request, arb_id_response, timeout
        )
        # Print results
        if print_results:
            for service_id in found_services:
                service_id_name = cls.UDS_SERVICE_NAMES.get(
                    service_id, "Unknown service"
                )
                print(
                    "Supported service 0x{0:02x}: {1}".format(
                        service_id, service_id_name
                    )
                )
        return found_services

    def __ecu_reset_wrapper(args):
        """Wrapper used to initiate ECU Reset"""
        logical_address = args.src
        reset_type = args.reset_type

        if not 1 <= reset_type <= 5:
            raise ValueError("reset type must be within interval 0x01-0x05")

        print(
            "Sending ECU reset, type 0x{0:02x} to arbitration ID 0x{1:02x}".format(
                reset_type, logical_address
            )
        )
        try:
            print("\nWaiting for Vehicle Identification Announcement\n")
            print(
                "Power cycle your ECU and wait for a few seconds for the broadcast to be received\n"
            )
            address, announcement = DoIPClient.await_vehicle_announcement()
            ip, port = address

            doip_client = DoIPClient(
                ip, logical_address, client_logical_address=args.dst
            )
            conn = DoIPClientUDSConnector(doip_client)
            with Client(conn, request_timeout=5) as client:
                client.ecu_reset(client, reset_type)

            print(doip_client.request_entity_status())

        except ConnectionRefusedError:
            print("Connection Refused: Please check the connection and try again.\n")

        except ConnectionResetError:
            print("Connection Reset: Please check the connection and try again.\n")

        except TimeoutError:
            print("Timeout Error: Please check the connection and try again.\n")

        except OSError:
            print("OSError: Please check the connection and try again.\n")

    @classmethod
    def dump_dids_initialiser(
        cls,
        server_file: str,
        save_folder: str,
        save_filename: str,
        client_id: int,
        network_adapter: str,
        timeout: float = 1,
        min_did=0x0000,
        max_did=0xFFFF,
        print_results=True,
        saving_method="csv",
        ecu_ip_address="169.254.99.220",
        whitelist=None,
        blacklist=None,
    ):
        servers_request = cls.read_servers_from_csv(server_file)

        def process_range(range_list):
            result = []
            for start, end in range_list:
                result.extend(range(start, end))
            return result

        whitelist_final = process_range(whitelist) if whitelist is not None else None
        blacklist_final = process_range(blacklist) if blacklist is not None else None

        if network_adapter is not None:
            discoverer = DOIP_Discoverer(
                connection_method="automatic",
                network_adapter=network_adapter,
            )
        else:
            discoverer = DOIP_Discoverer(ecu_ip_address, "entity")

        print(f"Dumping DIDs for Servers: {servers_request}")
        # logger = setup_logger()
        for server_request in servers_request:
            print("Requesting from server 0x{:0x}".format(server_request))
            responses = discoverer.dump_dids(
                server_request,
                client_id,
                timeout,
                min_did,
                max_did,
                print_results,
                whitelist_final,
                blacklist_final,
            )

            if saving_method == "csv":
                discoverer.save_data_to_csv(save_folder, responses, type="DIDs")
            elif saving_method == "database":
                database_file = os.path.join(
                    save_folder,
                    f"{save_filename}_{hex(server_request)}_{hex(client_id)}.db",
                )
                with DidRequestDatabase(database_file) as database:
                    database.reset_database()
                    database.store_list(responses)

        print("##############################")
        print("FINISHED DISCOVERY OF ALL IDS!")
        print("##############################")

    @classmethod
    def read_servers_from_csv(cls, csv_file):
        """
        Reads the found Servers from a CSV file.

        Parameters:
        - csv_file: The path to the CSV file.
        """
        print("Reading data from CSV file: " + csv_file)

        # Open a csv file to read the found arbitration ID pairs from
        with open(csv_file, "r") as file:
            # create the csv reader
            reader = csv.reader(file)

            # read the first row (headers)
            headers = next(reader)

            # read the remaining rows
            data = []
            for row in reader:
                hex_value = int(row[0], 16)
                data.append(hex_value)

        # close the file
        file.close()

        return data

    def dump_dids(
        self,
        server_id: int,
        client_id: int,
        timeout: float,
        min_did=DUMP_DID_MIN,
        max_did=DUMP_DID_MAX,
        print_results=True,
        whitelist=None,
        blacklist=None,
    ):
        """
        Sends read data by identifier (DID) messages to 'arb_id_request'.
        Returns a list of positive responses received from 'arb_id_response' within
        'timeout' seconds or an empty list if no positive responses were received.

        :param arb_id_request: arbitration ID for requests
        :param arb_id_response: arbitration ID for responses
        :param timeout: seconds to wait for response before timeout, or None
                        for default UDS timeout
        :param min_did: minimum device identifier to read
        :param max_did: maximum device identifier to read
        :param print_results: whether progress should be printed to stdout
        :type arb_id_request: int
        :type arb_id_response: int
        :type timeout: float or None
        :type min_did: int
        :type max_did: int
        :type print_results: bool
        :return: list of tuples containing DID and response bytes on success,
                empty list if no responses
        :rtype [(int, [int])] or []
        """
        # Sanity checks
        if isinstance(timeout, float) and timeout < 0.0:
            raise ValueError("Timeout value ({0}) cannot be negative".format(timeout))

        if max_did < min_did:
            raise ValueError(
                "max_did must not be smaller than min_did - got min:0x{0:x}, max:0x{1:x}".format(
                    min_did, max_did
                )
            )

        request_list = []
        timeout_counter = 0

        print("Discovering DIDs\n")
        try:
            doip_client = DoIPClient(
                ecu_ip_address=self.ip,
                initial_ecu_logical_address=server_id,
                client_logical_address=client_id,
                client_ip_address=self.client_ip_address,
            )
            conn = DoIPClientUDSConnector(doip_client)
            if print_results:
                print(
                    "Dumping DIDs in range 0x{:04x}-0x{:04x}\n".format(min_did, max_did)
                )

            client = Client(conn, request_timeout=timeout)
            self.extended_session(client, session_type=3)

            if whitelist is not None:
                didlist = whitelist
                if blacklist is not None:
                    didlist = [did for did in didlist if did not in blacklist]
            else:
                didlist = list(range(min_did, max_did + 1))
                if blacklist is not None:
                    didlist = [did for did in didlist if did not in blacklist]

            for identifier in didlist:
                print(f"\rProbing DID 0x{identifier:04x}", end="")
                try:
                    start_time = time.time()
                    response = client.read_data_by_identifier(identifier)
                    execution_time = time.time() - start_time

                    if (
                        execution_time > timeout
                    ):  # adding loop to stop if server continuously doesnt respond in time
                        timeout_counter += 1
                        if timeout_counter > 20:
                            print("Server responded continuously not in time.\n")
                            return request_list
                    else:
                        timeout_counter = 0

                    if response == None:
                        continue
                    elif response.positive == True:

                        byte1 = response.data[0]
                        byte2 = response.data[1]
                        identifier = (byte1 << 8) | byte2
                        # reason: sometimes the response is not the same as the request
                        # by that the identifier is correctly saved in the database

                        request_object = DoIPDidRequest(
                            server_id, client_id, identifier
                        )

                        request_object.history.payload_list.append(
                            self.bin_to_int(
                                response.data[2:]
                            )  # saves only the data of the response not the did
                        )
                        request_list.append(request_object)

                        if print_results:
                            print(
                                f"\rSUCCESS for DID: 0x{identifier:04x}, Data: {self.bin_to_int(response.data)}\n"
                            )

                except ConfigError:
                    sys.stderr = self.DevNull()
                    continue
            if print_results:
                print("\nDone!")
            return request_list

        except ConnectionRefusedError as e:
            print("Please check the connection and try again.\n")
            print(e)
            return request_list

        except ConnectionResetError as e:
            print("Please check the connection and try again.\n")
            print(e)
            return request_list

        except TimeoutError as e:
            print("Please check the connection and try again.\n")
            print(e)
            return request_list

        except OSError as e:
            print("Please check the connection and try again.\n")
            print(e)
            return request_list

    def bin_to_int(self, data):
        integers = [b for b in struct.unpack(f"{len(data)}B", data)]
        return integers

    def save_data_to_csv(self, csv_file, data, type="Servers"):
        """
        Saves the found arbitration ID pairs to a CSV file.

        Parameters:
        - csv_file: The path to the CSV file.
        - discovered_physical_addresses: The list of discovered physical addresses.
        - type: The type of the addresses. Can be "Servers" or "DIDs"
        """
        print("Saving data to CSV file: " + csv_file)
        os.makedirs(os.path.dirname(csv_file), exist_ok=True)
        # Open a csv file to write the found arbitration ID pairs to
        with open(csv_file, "w") as file:
            # create the csv writer
            writer = csv.writer(file)
            if type == "Servers":
                writer.writerow(
                    [
                        "Found Servers; Gateway Physical Address is {gateway_address}, Client Physical Address is {client_address}".format(
                            gateway_address=hex(self.logical_address),
                            client_address=hex(self.client_logical_address),
                        )  # type: ignore
                    ]
                )
            elif type == "DIDs":
                writer.writerow(["DID", "VALUE"])
            elif type == "DIDs_Performance":
                # check if file is empty
                if os.stat(csv_file).st_size == 0:
                    writer.writerow(["NUMBER OF DIDS", "RESPONSE_TIME", "DID", "VALUE"])

            for row in data:
                writer.writerow((row,))

        # close the file
        file.close()

    @classmethod
    def check_dids_performance_initialiser(
        cls,
        database_folder,
        csv_file_for_saving,
        interface: str,
        automatic=False,
        manual_version="largeDIDs",
        maximum_payload_length=-1,
    ):
        """
        Initialises the check_dids_performance function.

        Parameters:
        - database_folder: The folder where the database files are stored.
        - csv_file_for_saving: The path to the CSV file where the results should be saved.
        - gui_mode: If True, the function will be called from the GUI.
        """


        
        discoverer = DOIP_Discoverer(
            network_adapter=interface
        )
        if automatic:
            discoverer.check_dids_performance_automatic(
                database_folder, csv_file_for_saving, maximum_payload_length
            )
        else:
            discoverer.check_dids_performance(
                database_folder, csv_file_for_saving, manual_version
            )

    def check_dids_performance(self, database_folder, csv_file_for_saving, version):
        # store all databasefiles in a list
        servers = []
        files = []
        minimum_did = 1000  # set to a high number
        did_performance_list = []

        for file in os.listdir(database_folder):
            # iterate through all files in the folder
            if file.endswith(".db"):
                files.append(os.path.join(database_folder, file))

        for database_file in files:
            server = []
            with DidRequestDatabase(database_file) as database:
                did_requests = database.load_list(True)
                for did_request in did_requests:
                    server.append(did_request)
                servers.append(server)

        # perform dids performance for all servers in the database
        for server in servers:
            # strip the first two bytes in all entries of the json_history_payload
            result = []
            result.append(
                [
                    f"############### Server: {hex(server[0].ids.server_id)} ###############"
                ]
            )
            for did in server:
                did.history.payload_list[0] = did.history.payload_list[0][2:]
            # sort the list by the length of the json_history_payload, longest first
            if version == "largeDIDs":
                server.sort(key=lambda x: len(x.history.payload_list[0]), reverse=True)
            elif version == "smallDIDs":
                server.sort(key=lambda x: len(x.history.payload_list[0]), reverse=False)

            # start requesting the did and go until negative response from gateway
            doip_client = DoIPClient(
                self.ip,
                server[0].ids.server_id,
                client_logical_address=server[0].ids.tester_id,
            )
            conn = DoIPClientUDSConnector(doip_client)
            client = Client(conn, request_timeout=0.2)
            self.extended_session(client, session_type=3)
            did_counter = 0
            didlist: list[int] = []
            while did_counter <= len(server):
                did_counter += 1

                didlist.append(server[did_counter - 1].ids.did)
                start_time = time.time()
                response = client.read_data_by_identifier(didlist)
                response_time = (time.time() - start_time) * 1000

                if response == None:
                    if minimum_did > (
                        did_counter - 1
                    ):  # evaluate did and save the smalles in the whole performace test
                        minimum_did = did_counter - 1

                    did_performance_list.append(
                        [server[0].ids.server_id, did_counter - 1]
                    )
                    break
                elif response.positive == True:
                    result.append(
                        f"{did_counter}, {response_time:.0f} ms, {didlist}, {response.data[2:]}"
                    )

                    print(
                        "DID(s): ",
                        [hex(num) for num in didlist],
                        "Response: ",
                        [hex(num) for num in response.data[2:]],
                        "Response Time: ",
                        "{:.2f} ms".format(response_time),
                    )
                    continue
                if response.positive == False:
                    response.code
                    result.append("\n")
                    self.save_data_to_csv(
                        csv_file_for_saving, result, type="DIDs_Performance"
                    )
                    break
        print("###########################################")
        print("######### End of Performance Test #########")
        print("###########################################")

        return minimum_did, did_performance_list

    def check_dids_performance_automatic(
        self, database_folder: str, csv_file_for_saving: str, maximum_payload_length=-1
    ):
        """
        Algorithm to check the maximum dids and Payload Size for all servers in the database.
        Function:
        1. Iterate through all server files in the database folder and get maximum dids an a request, by addding the smallest dids first to the request.
        2. Repeat so by using the largest dids first.
        3. if the numbers of dids decreases, iterate with decreasing payload length until the maximum number of dids is reached and save the payload size
        """

        # store all databasefiles in a list
        servers = []
        files = []
        self.udsclient = DoIPConnector(self.con)
        # Beispielwerte für die Initialisierung des defaultdicts
        example_values = {"Server_ID": "0x0000", "DID_length": 0, "Payload_size": 0}
        # Erstellen des defaultdicts mit den angegebenen Schlüsseln und Beispielwerten
        performance_dict = defaultdict(lambda: example_values)

        for file in os.listdir(database_folder):
            # iterate through all files in the folder
            if file.endswith(".db"):
                files.append(os.path.join(database_folder, file))

        for database_file in files:
            server = []
            with DidRequestDatabase(database_file) as database:
                did_requests = database.load_list(True)
                for did_request in did_requests:
                    if maximum_payload_length != -1:
                        if did_request.ids.payload_length < maximum_payload_length:
                            server.append(did_request)
                        else:
                            continue
                servers.append(server)

        servers.sort(key=lambda x: x[0].ids.server_id, reverse=False)

        # perform dids performance for all servers in the database
        for server in servers:
            server.sort(
                key=lambda x: len(x.history.payload_list[0]), reverse=False
            )  # sort the list by the length of the json_history_payload, smallest first
            print(
                "############ Server: ", hex(server[0].ids.server_id), " ############"
            )
            result = []
            result.append(
                [
                    f"############### Server: {hex(server[0].ids.server_id)} ###############"
                ]
            )

            # start requesting the did and go until negative response from gateway
            client = self.udsclient.get_client(
                server_id=server[0].ids.server_id, tester_id=server[0].ids.tester_id
            )
            did_counter = 0
            didlist: list[int] = []
            no_response_counter = 0
            while did_counter < len(server):
                did_counter += 1

                didlist.append(server[did_counter - 1].ids.did)
                start_time = time.time()
                response = client.read_data_by_identifier(didlist, timeout=2)
                response_time = (time.time() - start_time) * 1000

                if response == None:
                    server_id = server[0].ids.server_id
                    performance_dict[server_id] = {"DID_length": len(didlist) - 1}
                    result.append("\n")
                    self.save_data_to_csv(
                        csv_file_for_saving, result, type="DIDs_Performance"
                    )
                    break

                elif response.positive == False:
                    if response.code == ResponseCode.RequestOutOfRange:
                        no_response_counter += 1
                        if no_response_counter > 5:
                            server_id = server[0].ids.server_id
                            performance_dict[server_id] = {
                                "DID_length": len(didlist) - 1
                            }
                            result.append("\n")
                            self.save_data_to_csv(
                                csv_file_for_saving, result, type="DIDs_Performance"
                            )
                            break
                        else:
                            didlist.pop()
                            continue
                    elif (
                        response.code == ResponseCode.ResponseTooLong
                        or response.code
                        == ResponseCode.IncorrectMessageLengthOrInvalidFormat
                    ):
                        server_id = server[0].ids.server_id
                        performance_dict[server_id] = {"DID_length": len(didlist) - 1}
                        result.append("\n")
                        self.save_data_to_csv(
                            csv_file_for_saving, result, type="DIDs_Performance"
                        )
                        break

                elif response.positive == True:
                    result.append(
                        [
                            did_counter,
                            f"{round(response_time,0)}ms",
                            str(didlist),
                            str(response.data[2:]),
                        ]
                    )

                    print(
                        "DID(s): ",
                        [hex(num) for num in didlist],
                        "Response: ",
                        [hex(num) for num in response.data[2:]],
                        "Response Time: ",
                        "{:.2f} ms".format(response_time),
                    )

                if did_counter == len(
                    server
                ):  # in case, the last DID is reached and not enough negative response is received
                    server_id = server[0].ids.server_id
                    performance_dict[server_id] = {"DID_length": len(didlist) - 1}
                    result.append("\n")
                    self.save_data_to_csv(
                        csv_file_for_saving, result, type="DIDs_Performance"
                    )
                    break

        # now perform the same with decreasing payload size
        result = []
        result.append(["################### Large DIDs ###################\n\n"])
        self.save_data_to_csv(csv_file_for_saving, result, type="DIDs_Performance")

        for server in servers:
            if not server[0].ids.server_id:
                continue

            server.sort(
                key=lambda x: len(x.history.payload_list[0]), reverse=True
            )  # sort the list by the length of the json_history_payload, largest first
            client = self.udsclient.get_client(
                server_id=server[0].ids.server_id, tester_id=server[0].ids.tester_id
            )
            result = []
            print(
                "############ Server: ",
                hex(server[0].ids.server_id),
                " Large DIDs ############",
            )
            result.append(
                [
                    f"############### Server: {hex(server[0].ids.server_id)} Large DIDs ###############"
                ]
            )

            # start requesting the did and go until negative response from gateway
            didlist: list[int] = []
            request_list: list[DoIPDidRequest] = []
            no_response_counter = 0
            did_counter = 0
            self.saved_to_csv = False
            start_time = time.time()
            while (
                did_counter < len(server)
                and len(didlist)
                < performance_dict[server[0].ids.server_id]["DID_length"]
            ):
                if time.time() - start_time > 20:
                    server = server[0].ids.server_id
                    performance_dict[server]["Payload_size"] = payload_length - (
                        (len(didlist) * 2) - 2
                    )
                    # reason: in the payload, each did (2 bytes each) is sent too. The first did is not in the payload.
                    result.append("\n")
                    self.save_data_to_csv(
                        csv_file_for_saving, result, type="DIDs_Performance"
                    )
                    break

                did_counter += 1

                request_list.append(server[did_counter - 1])
                didlist.append(server[did_counter - 1].ids.did)
                start_time = time.time()
                response = client.read_data_by_identifier(didlist)
                response_time = (time.time() - start_time) * 1000

                if response == None:  # if no response is received
                    if no_response_counter < 5:
                        no_response_counter += 1
                        continue
                    else:  # save the payload length and end the performance test for the server
                        payload_length = 0
                        for request in request_list:
                            payload_length += request.ids.payload_length
                        server = server[0].ids.server_id
                        performance_dict[server]["Payload_size"] = payload_length - (
                            (len(didlist) * 2) - 2
                        )

                        result.append("\n")
                        self.save_data_to_csv(
                            csv_file_for_saving, result, type="DIDs_Performance"
                        )
                        self.saved_to_csv = True
                        break

                elif response.positive == False:
                    if response.code == ResponseCode.RequestOutOfRange:
                        didlist.pop()
                        continue
                    elif response.code == ResponseCode.ResponseTooLong:
                        didlist.pop()
                        continue
                    else:  # end of performance test for server
                        payload_length = 0
                        for request in request_list:
                            payload_length += request.ids.payload_length

                        server = server[0].ids.server_id
                        performance_dict[server]["Payload_size"] = payload_length - (
                            (len(didlist) * 2) - 2
                        )
                        # assign the payload length to the server in the performance_dict

                        result.append("\n")
                        self.save_data_to_csv(
                            csv_file_for_saving, result, type="DIDs_Performance"
                        )
                        self.saved_to_csv = True
                        break

                elif response.positive == True:
                    result.append(
                        [
                            did_counter,
                            f"{round(response_time)}ms",
                            str(didlist),
                            str(response.data[2:]),
                        ]
                    )

                    print(
                        "DID(s): ",
                        [hex(num) for num in didlist],
                        "Response: ",
                        [hex(num) for num in response.data[2:]],
                        "Response Time: ",
                        "{:.2f} ms".format(response_time),
                    )
                    continue

            if not self.saved_to_csv:
                # in case, the last DID is reached and not enough negative response are received
                payload_length = 0
                for request in request_list:
                    payload_length += request.ids.payload_length

                server = server[0].ids.server_id
                performance_dict[server]["Payload_size"] = payload_length
                # assign the payload length to the server in the performance_dict

                result.append("\n")
                self.save_data_to_csv(
                    csv_file_for_saving, result, type="DIDs_Performance"
                )

        csv_file_config = csv_file_for_saving.replace(".csv", "_config_file.csv")
        with open(csv_file_config, "w") as file:
            writer = csv.writer(file)
            writer.writerow(["Server_ID", "DID Length", "Payload Size"])
            for key, value in performance_dict.items():
                if not value["Payload_size"]:
                    value["Payload_size"] = 0
                writer.writerow([hex(key), value["DID_length"], value["Payload_size"]])

        print("###########################################")
        print("######### End of Performance Test #########")
        print("###########################################")
