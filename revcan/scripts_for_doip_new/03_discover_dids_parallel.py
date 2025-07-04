import argparse
import sys
import time
from datetime import date
import logging
import os

from revcan.config import Config
from revcan.modules.caringcaribou.caringcaribou.modules.doip import DevNull
from revcan.reverse_engineering.models import car_metadata
from display_car_metadata import display_car_metadata
from revcan.reverse_engineering.models.car_metadata import Server
from revcan.signal_discovery.utils.doipclient import DoIPClient
from revcan.signal_discovery.utils.doipclient.connectors import DoIPClientUDSConnector

from revcan.signal_discovery.utils.udsoncan.client import Client
from revcan.signal_discovery.utils.udsoncan.exceptions import ConfigError
from revcan.signal_discovery.utils.udsoncan.services import DiagnosticSessionControl


def did_discovery(servers,
                  client_logical_address,
                  ecu_ip_address, 
                  possible_dids,
                  batch_size=8, 
                  timeout=1,
                  print_results=True,
                  activate_logging_flag=False,
):
    """
    Discover payload length for known servers and DIDs in a car model.

    Args:
        servers (List[Server]): List of servers to probe for DIDs.
        client_logical_address (int): The address that will receive the response from the ECU.
        ecu_ip_address (str): IP address of the ECU to connect to.
        possible_dids (List[int]): List of possible Data Identifiers (DIDs) to probe.
        timeout (int): Timeout in seconds for each request.
        print_results (bool): Flag to print progress.

    Returns:
        List[Server]: The list of servers with discovered parameters added.
    """

    for server in servers:

        # Check if discovery_complete_flag is set for current server and skip if so 
        if server.discovery_complete_flag and (server.first_unchecked_did_in_did_discovery > max(possible_dids)):
            if print_results:
                print(f"Discovery Complete for server 0x{server.id:04x} - Skipping this server")
            if activate_logging_flag:
                logging.info(f"Discovery Complete for server 0x{server.id:04x} - Skipping this server")
            continue

        possible_dids_server = [did for did in possible_dids if did >= server.first_unchecked_did_in_did_discovery]

        if not possible_dids_server:
            if print_results:
                print(f"The list of possible not tested DIDs is empty for server 0x{server.id:04x}. Skipping this server.")
            if activate_logging_flag:
                logging.info(f"The list of possible not tested DIDs is empty for server 0x{server.id:04x}. Skipping this server.")
            continue

        if print_results:
            print(f"Start probing dids for server 0x{server.id:04x}: Starting at did 0x{server.first_unchecked_did_in_did_discovery:04x}")
        if activate_logging_flag:
            logging.info(f"Start probing dids for server 0x{server.id:04x}: Starting at did 0x{server.first_unchecked_did_in_did_discovery:04x}")

        found_dids = []

        # Check if did_discovery_time_seconds is reset in the case of new discovery 
        if server.first_unchecked_did_in_did_discovery == 0 and server.did_discovery_time_seconds != 0:
            print("Error: did_discovery_time_seconds is not reset for server 0x{server.id:04x} even though starting with did 0x{server.first_unchecked_did_in_did_discovery:04x}. Please reset did_discovery_time_seconds_manually.")
            if activate_logging_flag:
                logging.warning("Error: did_discovery_time_seconds is not reset for server 0x{server.id:04x} even though starting with did 0x{server.first_unchecked_did_in_did_discovery:04x}. Please reset did_discovery_time_seconds_manually.")

        try:
            # Start measurement of time for did discovery process
            start_time = time.time()

            
            doip_client = DoIPClient(ecu_ip_address=ecu_ip_address, initial_ecu_logical_address=server.id,
                                     client_logical_address=client_logical_address)
            conn = DoIPClientUDSConnector(doip_client)
        
            for i in range(0, len(possible_dids_server), batch_size):
                did_batch = possible_dids_server[i:i+batch_size]

                if print_results:
                    print("\rProbing DIDs 0x{1:04x} to 0x{2:04x} for server 0x{0:04x}: found {3} - {4:.2f}% complete."
                          .format(server.id, did_batch[0], did_batch[-1], len(server.parameters), ((did_batch[-1] / max(possible_dids)) * 100)), end="")

                # Suppress lower-level messages
                if activate_logging_flag:
                    logging.getLogger().setLevel(logging.WARNING)
                
                # Establish a client to read data by identifier
                try:
                    with Client(conn, request_timeout=timeout) as client:
                        response = client.read_data_by_identifier(didlist=did_batch)
                except Exception as e:
                    print(f"An issue occurred while probing DIDs 0x{did_batch[0]:04x} to 0x{did_batch[-1]:04x} for server 0x{server.id:04x}: {e}")
                    if activate_logging_flag:
                        logging.warning(f"An issue occurred while probing DIDs 0x{did_batch[0]:04x} to 0x{did_batch[-1]:04x} for server 0x{server.id:04x}: {e}")

                # Acitvate lower-level messages again
                if activate_logging_flag:
                    logging.getLogger().setLevel(logging.INFO)

                #print(f"Response: {response}")
                # Check if batch size is to big
                if "NegativeResponse(IncorrectMessageLengthOrInvalidFormat)" in str(response):
                    print(f"The current batch size of {batch_size} is too big. Please reduce the batch size.")
                    end_time = time.time()
                    total_time = int(round(end_time - start_time))
                    server.did_discovery_time_seconds += total_time
                    print(f"\nDiscovery for server 0x{server.id:04x} interrupted. Time elapsed: {total_time} seconds.")
                    return servers

                # Check if found dids
                if not "NegativeResponse(RequestOutOfRange)" in str(response):               
                    # Check all dids in batch again
                    counter = 0
                    for did in did_batch:
                        counter += 1
                        if print_results:
                            print("\rProbing did 0x{1:04x} ({4}/{5}) from  for server 0x{0:04x}: found {2} - {3:.2f}% complete."
                                .format(server.id, did, len(server.parameters), ((did / max(possible_dids)) * 100), counter, batch_size), end="")

                        # Suppress lower-level messages
                        if activate_logging_flag:
                            logging.getLogger().setLevel(logging.WARNING)
                        
                        # Establish a client to read data by identifier
                        try:
                            with Client(conn, request_timeout=timeout) as client:
                                response = client.read_data_by_identifier_first(didlist=[did])
                        except Exception as e:
                            print(f"An issue occurred while probing DID 0x{did:04x} for server 0x{server.id:04x}: {e}")
                            if activate_logging_flag:
                                logging.warning(f"An issue occurred while probing DID 0x{did:04x} for server 0x{server.id:04x}: {e}")

                        # Acitvate lower-level messages again
                        if activate_logging_flag:
                            logging.getLogger().setLevel(logging.INFO)

                        # If DID found -> Save the parameter
                        # read first only returns the value or None
                        if response is not None and response != b'\x00':
                            length = len(response)
                            if server.parameters and server.parameters[-1].did == did:
                                server.parameters[-1].length = length
                            else:
                                server.parameters.append(car_metadata.Parameter(did=did, length=length))
                                found_dids.append(car_metadata.Parameter(did=did, length=length))
                                server.first_unchecked_did_in_did_discovery = did + 1
                            
                            if print_results:
                                print("\033[92m\rFound did 0x{1:04x} for server 0x{0:04x}: found {2}"
                                    .format(server.id, did, len(server.parameters)), end="")
                            if activate_logging_flag:
                                logging.info("Found did 0x{1:04x} for server 0x{0:04x}: found {2}"
                                            .format(server.id, did, len(server.parameters)))
                
                server.first_unchecked_did_in_did_discovery = did_batch[-1] + 1
                    
            print(f"\nDID discovery complete for server 0x{server.id:04x}.\n")
            if activate_logging_flag:
                logging.info(f"\nDID discovery complete for server 0x{server.id:04x}.\n")
            server.discovery_complete_flag = True
            # Save time measurements for did discovery
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            server.did_discovery_time_seconds += total_time

        except KeyboardInterrupt:
                    end_time = time.time()
                    total_time = int(round(end_time - start_time))
                    server.did_discovery_time_seconds += total_time
                    print(f"\nDiscovery for server 0x{server.id:04x} interrupted. Time elapsed: {total_time} seconds.")
                    return servers

        except ConnectionRefusedError:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            server.did_discovery_time_seconds += total_time
            print(f"\nDiscovery for server 0x{server.id:04x} interrupted. Time elapsed: {total_time} seconds.")
            print("Please check the connection and try again.\n")
            if activate_logging_flag:
                logging.info("Please check the connection and try again.\n")

        except ConnectionResetError:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            server.did_discovery_time_seconds += total_time
            print(f"\nDiscovery for server 0x{server.id:04x} interrupted. Time elapsed: {total_time} seconds.")
            print("Please check the connection and try again.\n")
            if activate_logging_flag:
                logging.info("Please check the connection and try again.\n")

        except TimeoutError:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            server.did_discovery_time_seconds += total_time
            print(f"\nDiscovery for server 0x{server.id:04x} interrupted. Time elapsed: {total_time} seconds.")
            print("Please check the connection and try again.\n")
            if activate_logging_flag:
                logging.info("Please check the connection and try again.\n")

        except BrokenPipeError:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            server.did_discovery_time_seconds += total_time
            print(f"\nBrokenPipeError occured for server 0x{server.id:04x} for DID 0x{did:04x}. Time elapsed: {total_time} seconds.")
            print(f"\nRestarting DID discovery.")
            if activate_logging_flag:
                logging.warning(f"\nBrokenPipeError occured for server 0x{server.id:04x} for DID 0x{did:04x}. Time elapsed: {total_time} seconds.")
                logging.warning(f"\nRestarting DID discovery.")
            return did_discovery(servers=servers,
                               client_logical_address = client_logical_address,
                               ecu_ip_address=ecu_ip_address, 
                               possible_dids=possible_dids,
                               batch_size=batch_size, 
                               timeout=timeout,
                               activate_logging_flag=activate_logging_flag)

        except OSError:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            server.did_discovery_time_seconds += total_time
            print(f"\nDiscovery for server 0x{server.id:04x} interrupted. Time elapsed: {total_time} seconds.")
            print("Please check the connection and try again.\n")
            if activate_logging_flag:
                logging.info("Please check the connection and try again.\n")
        


    return servers


def __did_discovery_wrapper(config_file_path, 
                            car_model_file_path,
                            reset_discovery_complete_flag=False,
                            activate_logging_flag=False,
):
    """
    Wrapper function used to initiate a DID discovery scan on the car model.

    Args:
        config_file_path (str): Path to the configuration file.
        car_model_file_path (str): Path to the car model file.
    """
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
    
    # Setup Logging if flag is set
    if activate_logging_flag:
        logging_file_path = os.path.dirname(car_model_file_path) + '/logging/'
        car_model_file_name = os.path.splitext(os.path.basename(car_model_file_path))[0]
        logging.basicConfig(
            filename=logging_file_path + car_model_file_name + '_did-discovery.log',
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

    #client_logical_address = car.client_logical_address
    client_logical_address = car.arb_id_pairs[0].client_logical_address

    if client_logical_address is None:
        print("arb_id_response not found in the configuration.")
        return

    timeout = doip_config.get("service_discovery_timeout")
    batch_size = doip_config.get("batch_size")
    ecu_ip_address = config.get(f"vehicles.{car.model}_{car.vin}_ip_address")

    whitelist = [[0x0000, 0xFFFF]]

    blacklist = []

    
    # small helper function to transform the lists of ranges into a single list
    def process_range(range_list):
        result = []
        for start, end in range_list:
            result.extend(range(start,end + 1))
        return result

    whitelist = process_range(whitelist)
    blacklist = process_range(blacklist)
    

    # Remove blacklisted items from the whitelist
    dids_whitelist_wo_blacklist = [did for did in whitelist if did not in blacklist]

    # Reset discovery complete flag for all servers if reset_discovery_complete_flag is set to true
    if reset_discovery_complete_flag:
        for server in car.servers:
            server.discovery_complete_flag = False
            server.first_unchecked_did_in_did_discovery = 0
            server.parameters = []

    # Probe dids
    car.servers = did_discovery(servers=car.servers,
                               client_logical_address = client_logical_address,
                               ecu_ip_address=ecu_ip_address,
                               batch_size=batch_size, 
                               possible_dids=dids_whitelist_wo_blacklist, 
                               timeout=timeout,
                               activate_logging_flag=activate_logging_flag)
    

    try:
        car.save(car_model_file_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_file_path}' was not found.")
        if activate_logging_flag:
            logging.warning(f"Error: The car model file at '{car_model_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving car model: {e}")
        if activate_logging_flag:
            logging.warning(f"Error saving car model: {e}")
        return

    print("\n")
    display_car_metadata(car)

if __name__ == "__main__":
    # Parse command-line arguments for configuration and car model paths
    argparser = argparse.ArgumentParser(
        description="Discover DIDs of connected Vehicle"
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
    argparser.add_argument(
        "--reset_discovery_complete_flag",
        dest="reset_discovery_complete_flag",
        type=bool,
        help="Flag that indicates whether to reset the discovery complete flag",
    )
    argparser.add_argument(
        "--activate_logging_flag",
        dest="activate_logging_flag",
        type=bool,
        help="Flag that indicates whether to log the progress of the did discovery",
    )
    args = argparser.parse_args()

    __did_discovery_wrapper(args.config_file_path, args.car_model_path, args.reset_discovery_complete_flag, args.activate_logging_flag)
