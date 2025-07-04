from revcan.signal_discovery.utils.udsoncan import ConfigError

from revcan.config import Config

from revcan.modules.caringcaribou.caringcaribou.utils.constants import ARBITRATION_ID_MAX, ARBITRATION_ID_MAX_EXTENDED, \
    BYTE_MAX
from revcan.modules.caringcaribou.caringcaribou.utils.constants import ARBITRATION_ID_MIN

from revcan.signal_discovery.utils.doipclient import DoIPClient
from revcan.signal_discovery.utils.doipclient.connectors import DoIPClientUDSConnector
from revcan.signal_discovery.utils.udsoncan.client import Client
from revcan.signal_discovery.utils.udsoncan.services import *
from sys import stdout
import argparse
import datetime
import time
import sys
import struct

from revcan.modules.caringcaribou.caringcaribou.modules.doip import BYTE_MIN, DevNull
from revcan.reverse_engineering.models import car_metadata


def uds_discovery(car: car_metadata.Car,
                  config: Config,
                  min_id, 
                  max_id, 
                  blacklist_args, 
                  auto_blacklist_duration,
                  delay, 
                  print_results=True
                  )->[(int,int)]:
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
        raise ValueError("max_id must not be smaller than min_id - got min:0x{0:x}, max:0x{1:x}".format(min_id, max_id))
    if auto_blacklist_duration < 0:
        raise ValueError("auto_blacklist_duration must not be smaller than 0, got {0}'".format(auto_blacklist_duration))
    elif auto_blacklist_duration > 0:
        timeout = auto_blacklist_duration
    else:
        timeout = 2

    blacklist = set(blacklist_args)

    found_arbitration_ids = []

    client_logical_address= min_id - 1

    print("Waiting for Vehicle Identification Announcement\n")
    print("Power cycle your ECU and wait for a few seconds for the broadcast to be received\n")
    address, announcement = DoIPClient.await_vehicle_announcement()
    ecu_logical_address = announcement.logical_address
    ip, port = address
    set_vehicle_ip(config=config, 
                   car=car,
                   ip=ip)
    print("ECU IP and port found: ", ip, ",", port, "\nECU Logical Address Found: ", hex(ecu_logical_address), "\n")

    print("Searching for Client Node ID\n")

    client_id_status = 0
    while client_logical_address < max_id:

        client_logical_address += 1
        if print_results:
            print("\rSending Diagnostic Session Control to 0x{0:04x}"
                  .format(client_logical_address), end="")

        try:
            if client_logical_address in blacklist:
                # Ignore blacklisted arbitration IDs
                continue

            if client_id_status == 0:
                doip_client = DoIPClient(ip, ecu_logical_address, client_logical_address=client_logical_address)
            else:
                doip_client = DoIPClient(ip, ecu_logical_address, client_logical_address=client_logical_address)

            conn = DoIPClientUDSConnector(doip_client)
            with Client(conn, request_timeout=timeout) as client:
                response = client.change_session(DiagnosticSessionControl.Session.defaultSession)
            if response.positive:
                print("\n\nFound diagnostics server "
                      "listening at 0x{0:04x}, "
                      "response at 0x{1:04x}"
                      .format(ecu_logical_address, client_logical_address))
                found_arb_id_pair = (ecu_logical_address, client_logical_address)
                found_arbitration_ids.append(found_arb_id_pair)

                if client_id_status == 0:
                    client_id_status = 1
                    client_logical_address = client_logical_address
                    client_logical_address = min_id - 1
                    print("\nSearching for Server Node ID\n")
                else:
                    continue
            else:
                blacklist.add(client_logical_address)

        except KeyboardInterrupt:
            return found_arbitration_ids
        except ConnectionRefusedError:
            time.sleep(delay)

        except ConnectionResetError:
            time.sleep(delay)
            continue

        except TimeoutError:
            sys.stderr = DevNull()
            continue

        except OSError:
            print("Please check the connection and try again.\n")

    return found_arbitration_ids

def __uds_discovery_wrapper(config_file_path: str, car_model_file_path: str):
    """Wrapper used to initiate a UDS discovery scan"""
    #ID Overview as per ISO/DIS 13400-2:2024
    '''
    0x0000 ISO/SAE reserved
    0x0001 - 0x0DFF VM specific
    0x0E00 - 0x0E7F external legislated diagnostic test equipment
    0x0E80 - 0x0EFF external vehicle-manufacturer/aftermarket-enhanced diagnostic test equipment
    0x0F00 - 0x0F7F internal data collection /on-board diagnostic equipment (for vehicle-manufacturer use only)
    0x0F80 - 0x0FFF external prolonged data collection equipment (vehicle data recorders and loggers, e.g. used by insurance companies or to collect vehicle fleet data)
    0x1000 - 0x7FFF VM specific
    0x8000 - 0xCFFF reserved by ISO/DIS 13400-2:2024
    0xD000 - 0xDFFF reserved for AE Truck & Bus Control and Communication Comitee
    0xE000 - 0xE3FF Definition of logical address is specified in use-case specific standard (ISO 27145-1, ISO 20730)
    0xE400 - 0xEFFF vehicle manufacturer defined functional group logical addresses
    0xF000 - 0xFFFF reserved by ISO/DIS 13400-2:2024
    '''
    min_id = 0x0E80
    max_id = 0x0EFF
    blacklist = []
    auto_blacklist_duration = 2 
    delay = 0.5 
    print_results = False 

    config = Config(config_file_path)

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


    try:
        arb_id_pairs = uds_discovery(car=car,
                                     config=config,
                                     min_id=min_id, 
                                     max_id=max_id,
                                     blacklist_args=blacklist,auto_blacklist_duration=auto_blacklist_duration,
                                     delay=delay,
                                     print_results=print_results)
        if len(arb_id_pairs) == 0:
            # No UDS discovered
            print("\nDiagnostics service could not be found.")
        else:
            # Print result table
            print("\nIdentified diagnostics:\n")
            table_line = "+------------+------------+"
            print(table_line)
            print("| CLIENT ID  | SERVER ID  |")
            print(table_line)
            for (client_id, server_id) in arb_id_pairs:
                print("| 0x{0:08x} | 0x{1:08x} |"
                      .format(client_id, server_id))
            print(table_line)
            car.arb_id_pairs = arb_id_pairs
            car.save(car_model_file_path)
    except ValueError as e:
        print("Discovery failed: {0}".format(e))


def set_vehicle_ip(config: Config,
                   car: car_metadata.Car,
                   ip: str):
    if ip is None:
        print(f"ERROR: IP address of vehicle not found.")
        return

    # Add or update the car model's IP address
    config.set(f"vehicles.{car.model}_{car.vin}_ip_address", ip)

    # Save the updated configuration to the YAML file
    try:
        config.save()
        print(f"Updated config file with {car.model}_{car.vin}_ip_address: {ip}")
    except Exception as e:
        print(f"Failed to update the config file: {e}")



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

    __uds_discovery_wrapper(args.config_file_path, args.car_model_path)