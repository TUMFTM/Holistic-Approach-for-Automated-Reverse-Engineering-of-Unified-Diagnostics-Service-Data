from revcan.signal_discovery.utils.udsoncan import ConfigError
from revcan.signal_discovery.utils.udsoncan.client import Client

from revcan.config import Config
from revcan.modules.caringcaribou.caringcaribou.modules.doip import extended_session
from revcan.modules.caringcaribou.caringcaribou.utils.common import list_to_hex_str, parse_int_dec_or_hex
from revcan.modules.caringcaribou.caringcaribou.utils.constants import ARBITRATION_ID_MAX, ARBITRATION_ID_MAX_EXTENDED, \
    BYTE_MAX
from revcan.modules.caringcaribou.caringcaribou.utils.constants import ARBITRATION_ID_MIN
from revcan.modules.caringcaribou.caringcaribou.utils.iso14229_1 import Constants, NegativeResponseCodes
from revcan.signal_discovery.utils.doipclient import DoIPClient
from revcan.signal_discovery.utils.doipclient.connectors import DoIPClientUDSConnector

from revcan.signal_discovery.utils.udsoncan.services import *
from sys import stdout
import argparse
import datetime
import time
import sys
import struct

from revcan.modules.caringcaribou.caringcaribou.modules.doip import BYTE_MIN, DevNull, PAYLOAD_TYPE, UDS_SERVICE_NAMES
from revcan.reverse_engineering.models import car_metadata


def service_discovery(ecu_logical_address, client_logical_address, ecu_ip_address, timeout,
                      min_id=BYTE_MIN, max_id=BYTE_MAX, print_results=True):
    """Scans for supported UDS services on the specified arbitration ID.
       Returns a list of found service IDs.

    :param ecu_logical_address: arbitration ID for requests
    :param client_logical_address: arbitration ID for responses
    :param timeout: delay between each request sent
    :param min_id: first service ID to scan
    :param max_id: last service ID to scan
    :param print_results: whether progress should be printed to stdout
    :type ecu_logical_address: int
    :type client_logical_address: int
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
                print("\rProbing service 0x{0:02x} ({0}/{1}): found {2}; "
                      .format(service_id, max_id, len(found_services)),
                      end="")
            stdout.flush()

            doip_client = DoIPClient(ecu_ip_address, ecu_logical_address, client_logical_address=client_logical_address)

            conn = DoIPClientUDSConnector(doip_client)

            s = struct.pack("<h", service_id)

            doip_message = struct.pack("!HH", client_logical_address, ecu_logical_address) + s[:1] + b"\x00"

            try:
                with Client(conn, request_timeout=timeout) as client:
                    extended_session(client, session_type=3)

                    doip_client.send_doip(PAYLOAD_TYPE, doip_message)
                    response = doip_client.receive_diagnostic(timeout)

                    doip_client.close()

                    if response is None or response[2] == NegativeResponseCodes.SERVICE_NOT_SUPPORTED:
                        continue

                    if response[2] == NegativeResponseCodes.SUB_FUNCTION_NOT_SUPPORTED or \
                            response[2] == NegativeResponseCodes.INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT:
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
                sys.stderr = DevNull()
                time.sleep(3)
                continue
            except OSError:
                sys.stderr = DevNull()
                time.sleep(3)
                continue
            except IndexError:
                sys.stderr = DevNull()
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


def __service_discovery_wrapper(config_file_path, car_model_file_path):
    """Wrapper used to initiate a service discovery scan"""
    # Load config
    config = Config(config_file_path)
    doip_config = config.get("doip")

    # Try to load car_model_path
    try:
        car = car_metadata.Car.load(car_model_file_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading car model: {e}")
        return

    # Try to save car_model_path
    try:
        car.save(car_model_file_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving car model: {e}")
        return

    

    arb_id_request = car.arb_id_pairs[0].ecu_logical_address
    arb_id_response = car.arb_id_pairs[0].client_logical_address
    timeout = doip_config.get("service_discovery_timeout")
    ecu_ip_address = config.get(f"vehicles.{car.model}_{car.vin}_ip_address")
    # Probe services
    found_services = service_discovery(arb_id_request,
                                       arb_id_response, ecu_ip_address, timeout)
    if found_services: # check if services were found
        car.services = [] # Reset list of services first
        for service_id in found_services:
            service_id_name = UDS_SERVICE_NAMES.get(service_id, "Unknown service")
            print("Supported service 0x{0:02x}: {1}".format(service_id, service_id_name))
            car.services.append(car_metadata.Service(id=service_id, name=service_id_name))
        
        try:
            car.save(car_model_file_path)
        except FileNotFoundError:
            print(f"Error: The car model file at '{car_model_file_path}' was not found.")
            return
        except Exception as e:
            print(f"Error saving car model: {e}")
            return


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(
        description="Discover UDS Servers of connected Vehicle"
    )
    argparser.add_argument(
        "--config_file_path",
        dest="config_file_path",
        type=str,
        help="Path to config file",
    )
    argparser.add_argument(
        "--car_model_path",
        dest="car_model_path",
        type=str,
        help="Path to car model",
    )
    args = argparser.parse_args()

    __service_discovery_wrapper(args.config_file_path, args.car_model_path)