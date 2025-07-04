import json
import argparse
import sys
import time
import logging
import os
from datetime import date
from pathlib import Path
from revcan.signal_discovery.utils.udsoncan.client import Client
from revcan.signal_discovery.utils.doipclient.connectors import DoIPClientUDSConnector
from revcan.signal_discovery.utils.udsoncan.services import DiagnosticSessionControl

from revcan.config import Config
from revcan.reverse_engineering.models import car_metadata
from display_car_metadata import display_car_metadata
from revcan.signal_discovery.utils.doipclient import DoIPClient



def request_ecu_metadata(client: Client, server: car_metadata.Server):
    metadata_dids=[0xf180, 0xf181, 0xf182, 0xf183,0xf184, 0xf185,0xf186,0xf187,0xf188,0xf189,0xf18A,0xf18B,0xf18C,0xf18D,0xf18E,0xf18F,0xf190,0xf191,0xf192,0xf193,0xf194,0xf195,0xf196,0xf197,0xf198,0xf199,0xf19A,0xf19B,0xf19C,0xf19D,0xf19E,0xf19F ]

    for did in metadata_dids:
        response = client.read_data_by_identifier_first(didlist=[did])

        if response is None:
            continue

        if isinstance(response, bytes):
            try:
                response = response.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    response = response.decode('latin-1')
                except UnicodeDecodeError:
                    print(f"Warning: Could not decode response for DID {did}.")
                    response = ""
            
            match did:
                    case 0xf180 :
                        server.BootSoftwareIdentificationDataIdentifier = response
                    case 0xf181:
                        server.applicationSoftwareIdentificationDataIdentifier = response
                    case 0xf182:
                        server.applicationDataIdentificationDataIdentifier = response
                    case 0xf183:
                        server.bootSoftwareFingerprintDataIdentifier = response
                    case 0xf184:
                        server.applicationSoftwareFingerprintDataIdentifier = response
                    case 0xf185:
                        server.applicationDataFingerprintDataIdentifier = response
                    case 0xf186:
                        server.ActiveDiagnosticSessionDataIdentifier = response
                    case 0xf187:
                        server.vehicleManufacturerSparePartNumberDataIdentifier = response
                    case 0xf188:
                        server.vehicleManufacturerECUSoftwareNumberDataIdentifier = response
                    case 0xf189:
                        server.vehicleManufacturerECUSoftwareVersionNumberDataIdentier = response
                    case 0xf18A:
                        server.systemSupplierIdentifierDataIdentifier = response
                    case 0xf18B:
                        server.ECUManufacturingDateDataIdentifier = response
                    case 0xf18C:
                        server.ECUSerialNumberDataIdentifier = response
                    case 0xf18D:
                        server.supportedFunctionalUnitsDataIdentifier = response
                    case 0xf18E:
                        server.VehicleManufacturerKitAssemblyPartNumberDataIdentifier = response
                    case 0xf18F:
                        server.RegulationXSoftwareIdentificationNumbers = response
                    case 0xf190:
                        server.VINDataIdentifier = response
                    case 0xf191:
                        server.vehicleManufacturerECUHardwareNumberDataIdentifier = response
                    case 0xf192:
                        server.systemSupplierECUHardwareNumberDataIdentifier = response
                    case 0xf193:
                        server.systemSupplierECUHardwareVersionNumberDataIdentifier = response
                    case 0xf194:
                        server.systemSupplierECUSoftwareNumberDataIdentifier = response
                    case 0xf195:
                        server.systemSupplierECUSoftwareVersionNumberDataIdentifier = response
                    case 0xf196:
                        server.exhaustRegulationOrTypeApprovalNumberDataIdentifier = response
                    case 0xf197:
                        server.systemNameOrEngineTypeDataIdentifier = response
                    case 0xf198:
                        server.repairShopCodeOrTesterSerialNumberDataIdentifier = response
                    case 0xf199:
                        server.programmingDateDataIdentifier = response
                    case 0xf19A:
                        server.calibrationRepairShopCodeOrCalibrationEquipmentSerialNumberDataIdentifier = response
                    case 0xf19B:
                        server.calibrationDateDataIdentifier = response
                    case 0xf19C:
                        server.calibrationEquipmentSoftwareNumberDataIdentifier = response
                    case 0xf19D:
                        server.ECUInstallationDateDataIdentifier = response
                    case 0xf19E:
                        server.ODXFileDataIdentifier = response
                    case 0xf19E:
                        server.EntityDataIdentifier = response
                    case _:
                        print("unknown did requested")


def __wrapper_request_ecu_metadata(config_file_path: str, 
                                   car_model_path: str,
                                   delay=0.0,
                                   timeout=1,
                                   print_results=True):
    # Load config
    config = Config(config_file_path)
    doip_config = config.get("doip")

    # Try to load car_model_path
    try:
        car = car_metadata.Car.load(car_model_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading car model: {e}")
        return

    # Try to save car_model_path
    try:
        car.save(car_model_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving car model: {e}")
        return

    client_logical_address = car.arb_id_pairs[0].client_logical_address

    if client_logical_address is None:
        print("client_logical_address not found in the configuration.")
        return

    current_count = 0

    for server in car.servers:
        current_count+=1
        try:
            doip_client = DoIPClient(
                ecu_ip_address=config.get(f"vehicles.{car.model}_{car.vin}_ip_address"),
                initial_ecu_logical_address=server.id,
                client_logical_address=client_logical_address,
                # client_ip_address=self.client_ip_address,
            )
            conn = DoIPClientUDSConnector(doip_client)

            with Client(
                    conn, request_timeout=timeout) as client:
                response = client.change_session(
                    DiagnosticSessionControl.Session.defaultSession
                )
            
            if print_results:
                print(f"Requesting ECU metadata for server 0x{server.id:04x}: {current_count}/{len(car.servers)}")

            # Request ECU metadata for discovered server
            with Client(conn, request_timeout=timeout) as client:
                request_ecu_metadata(client, car.servers[-1])
        
        except KeyboardInterrupt:
            return
        except ConnectionRefusedError:
            time.sleep(delay)
        except ConnectionResetError:
            time.sleep(delay)
            continue
        except TimeoutError:
            #sys.stderr = self.DevNull()
            continue
        except OSError:
            return
        
        # Catch all unexpected exceptions and make sure everything is saved before leaving.
        except Exception:
            return
    
    car.save(car_model_path)

def uds_server_discovery(
        car: car_metadata.Car,
        ecu_ip_address: str,
        min_id=0x0000,
        max_id=0xFFFF,
        blacklist=[],
        delay=0.0,
        timeout=1,
        print_results=True,
        activate_logging_flag=False,
        client_logical_address:int=None,
):
    """
    Discover UDS servers using the specified parameters.

    Args:
        ecu_ip_address (str): The network adapter to use for discovery.
        min_id (int): The minimum arbitration ID to consider.
        max_id (int): The maximum arbitration ID to consider.
        blacklist (list): A list of blacklisted ID ranges.
        auto_blacklist_duration (float): Duration for which to blacklist an address.
        delay (float): Delay between requests.
        print_results (bool): Whether to print the discovery results.
        client_logical_address (str): Logical address of the client.

    Returns:
        list: A list of discovered servers.
    """

    # adds all the blacklisted addresses to the blacklist
    blacklist_final = []
    for i in blacklist:
        numbers = list(range(i[0], i[1]))
        for number in numbers:
            blacklist_final.append(number)
    found_servers=[]
    server_id = min_id-1
    start_time = time.time()
    while server_id < max_id:
        server_id += 1

        if server_id in blacklist:
            # Ignore blacklisted arbitration IDs
            continue

        if print_results:
            print("\rSending Diagnostic Session Control to 0x{0:04x}: found {1} - {2:.2f}% complete."
                  .format(server_id, len(car.servers), ((server_id / max_id) * 100)),end="")
        if activate_logging_flag:
            logging.info("Sending Diagnostic Session Control to 0x{0:04x}: found {1} - {2:.2f}% complete."
                  .format(server_id, len(car.servers), ((server_id / max_id) * 100)))

        # Suppress lower-level messages
        if activate_logging_flag:
            logging.getLogger().setLevel(logging.WARNING)

        try:
            doip_client = DoIPClient(
                ecu_ip_address=ecu_ip_address,
                initial_ecu_logical_address=server_id,
                client_logical_address=client_logical_address,
                # client_ip_address=self.client_ip_address,
            )
            conn = DoIPClientUDSConnector(doip_client)

            with Client(
                    conn, request_timeout=timeout) as client:
                response = client.change_session(
                    DiagnosticSessionControl.Session.defaultSession
                )

            # Acitvate lower-level messages again
            if activate_logging_flag:
                logging.getLogger().setLevel(logging.INFO)

            if response == None:
                continue
            elif response.positive:
                print(
                    "\n\nFound diagnostics server "
                    "listening at 0x{0:04x}, "
                    "response at 0x{1:04x}".format(client_logical_address, server_id)
                )
                if activate_logging_flag:
                    logging.info("\n\nFound diagnostics server "
                        "listening at 0x{0:04x}, "
                        "response at 0x{1:04x}".format(client_logical_address, server_id))
                # # adds the found servers to the list;
                # # the loop asures that only the ecu addresses are added and not the tester
                # if client_id_status == 1:
                found_servers.append(hex(server_id))
                if not car.servers or server_id != car.servers[-1].id:
                    car.servers.append(car_metadata.Server(id=server_id, max_payload_length=-1, parameters=[]))
                
                # Request ECU metadata for discovered server
                try:
                    with Client(conn, request_timeout=timeout) as client:
                        request_ecu_metadata(client, car.servers[-1])
                except Exception as e:
                    print(f"\033[91mError while requesting metadata for server 0x{server_id:04x}: {e}")
                    if activate_logging_flag:
                        logging.warning(f"\033[91mError while requesting metadata for server 0x{server_id:04x}: {e}")
                    continue    

            else:
                blacklist.add(server_id)

        except KeyboardInterrupt:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            car.server_discovery_time_seconds += total_time
            car.first_unchecked_server_id_in_server_discovery = server_id
            print(f"\nServer Discovery interrupted. Time elapsed: {total_time} seconds.")
            if activate_logging_flag:
                logging.warning(f"\nServer Discovery interrupted. Time elapsed: {total_time} seconds.")
            return
        except ConnectionRefusedError as e:
            print(f"\nServer Discovery interrupted. ConnectionRefusedError: {e}")
            if activate_logging_flag:
                logging.warning(f"\nServer Discovery interrupted. ConnectionRefusedError: {e}")
            time.sleep(delay)
        except ConnectionResetError as e:
            print(f"\nServer Discovery interrupted. ConnectionResetError: {e}")
            if activate_logging_flag:
                logging.warning(f"\nServer Discovery interrupted. ConnectionResetError: {e}")
            time.sleep(delay)
            continue
        except TimeoutError as e:
            #sys.stderr = self.DevNull()
            print(f"\nServer Discovery interrupted. TimeoutError: {e}")
            if activate_logging_flag:
                logging.warning(f"\nServer Discovery interrupted. TimeoutError: {e}")
            continue
        except OSError as e:
            end_time = time.time()
            total_time = int(round(end_time - start_time))
            car.server_discovery_time_seconds += total_time
            car.first_unchecked_server_id_in_server_discovery = server_id
            print(f"\nServer Discovery interrupted. OSError: {e}")
            print("Please check the connection and try again.\n")
            if activate_logging_flag:
                logging.warning(f"\nServer Discovery interrupted. OSError: {e}")
            return
        
        # Catch all unexpected exceptions and make sure everything is saved before leaving.
        except Exception:
            car.first_unchecked_server_id_in_server_discovery = server_id
            return

    end_time = time.time()
    total_time = int(round(end_time - start_time))
    car.server_discovery_time_seconds += total_time
    car.first_unchecked_server_id_in_server_discovery = max_id+1
    return



def dump_servers(config_file_path: str, 
                 car_model_path: str, 
                 reset_server_discovery_flag=False,
                 activate_logging_flag=False,
):
    """
    Discover UDS servers from the specified car model and configuration file.

    Args:
        configFile (str): Path to the configuration file.
        car_model_path (str): Path to the car model file.
    """
    # Load config
    config = Config(config_file_path)
    doip_config = config.get("doip")

    # Try to load car_model_path
    try:
        car = car_metadata.Car.load(car_model_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading car model: {e}")
        return

    # Try to save car_model_path
    try:
        car.save(car_model_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving car model: {e}")
        return

    if activate_logging_flag:
        logging_file_path = os.path.dirname(car_model_path) + '/logging/'
        Path(logging_file_path).mkdir(parents=True, exist_ok=True)
        car_model_file_name = filename_without_extension = os.path.splitext(os.path.basename(car_model_path))[0]
        logging.basicConfig(
            filename=logging_file_path + car_model_file_name + '_server-discovery.log',
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

    # Check if reset_server_discovery_flag is set
    if reset_server_discovery_flag:
        car.servers = []
        car.first_unchecked_server_id_in_server_discovery = 0
        car.server_discovery_time_seconds = 0
        print("Successfully reset server list of provided car model.")
        if activate_logging_flag:
            logging.info("Successfully reset server list of provided car model.")

   
    client_logical_address = car.arb_id_pairs[0].client_logical_address

    if client_logical_address is None:
        print("client_logical_address not found in the configuration.")
        if activate_logging_flag:
            logging.warning("client_logical_address not found in the configuration.")
        return

    uds_server_discovery(
        car,
        ecu_ip_address=config.get(f"vehicles.{car.model}_{car.vin}_ip_address"),
        client_logical_address=client_logical_address,
        min_id=car.first_unchecked_server_id_in_server_discovery,
        activate_logging_flag=activate_logging_flag,
    )
    
    car.save(car_model_path)
    print("\n")
    display_car_metadata(car)


if __name__ == "__main__":
    # Parse command-line arguments for configuration and car model paths
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
    argparser.add_argument(
        "--reset_server_discovery_flag",
        dest="reset_server_discovery_flag",
        type=bool,
        help="Flag that indicates whether to reset the server discovery",
    )
    argparser.add_argument(
        "--request_ecu_metadata_only_flag",
        dest="request_ecu_metadata_only_flag",
        type=bool,
        help="Flag that indicates whether to only request the ECU Metadata for all already found servers. If flag is set no server discovery will be performed.",
    )
    argparser.add_argument(
        "--activate_logging_flag",
        dest="activate_logging_flag",
        type=bool,
        help="Flag that indicates whether to log the progress of the server discovery",
    )
    args = argparser.parse_args()

    if args.request_ecu_metadata_only_flag:
        __wrapper_request_ecu_metadata(args.config_file_path, args.car_model_path)
    else:
        dump_servers(args.config_file_path, args.car_model_path, args.reset_server_discovery_flag, args.activate_logging_flag)