import argparse
import sys
import time
import datetime
import logging
import os

from collections import defaultdict

from revcan.config import Config
from revcan.modules.caringcaribou.caringcaribou.modules.doip import DevNull
from revcan.reverse_engineering.models import car_metadata
from revcan.reverse_engineering.models.car_metadata import Server
from revcan.reverse_engineering.models.experiment import Experiment, Value
from revcan.signal_discovery.utils.doipclient import DoIPClient
from revcan.signal_discovery.utils.doipclient.connectors import DoIPClientUDSConnector

from revcan.signal_discovery.utils.udsoncan.client import Client
from revcan.signal_discovery.utils.udsoncan.exceptions import ConfigError
from revcan.signal_discovery.utils.udsoncan.services import DiagnosticSessionControl


def read_data(    experiment:Experiment,
                  client_logical_address,
                  ecu_ip_address,
                  num_samples: int=1,
                  timeout=1,
                  print_results=True,
                  activate_logging_flag=False,
                  continue_read:bool=False
):
    #sort measurements in order to have a higher chance to re-use already established connections
    experiment.measurements.sort(key= lambda x: x.serverid)
    experiment.starttime = datetime.datetime.now()
    
    # Set default value of measurements to 1 
    if num_samples == None:
        num_samples = 1
    
    # Set num_samples_name for print statements
    if num_samples == -1:
        num_samples_name = "∞"
    else:
        num_samples_name = num_samples
    
    signals_total_num = len(experiment.measurements)

    # Check if continue_read flag is set
    if continue_read and (len(experiment.measurements[-1].values)+1 == len(experiment.measurements[-1].values)):
        sample_counter = len(experiment.measurements[-1].values)
    else:
        sample_counter = 0

    try:
        # Establish a connection with server of first signal
        if experiment.measurements:
            last_server_id = experiment.measurements[0].serverid
            doip_client = DoIPClient(ecu_ip_address=ecu_ip_address, initial_ecu_logical_address=last_server_id,
                                                client_logical_address=client_logical_address)
            conn = DoIPClientUDSConnector(doip_client)
        else:
            print(f"Error: No signals found in measurements. experiment.measurements={experiment.measurements}")
            if activate_logging_flag:
                logging.warning(f"Error: No signals found in measurements. experiment.measurements={experiment.measurements}")
            return experiment

        start_time = time.time()
        while (sample_counter < num_samples or num_samples == -1):
            sample_counter += 1
            signal_counter = 0
            for signal in experiment.measurements:
                signal_counter += 1
                if continue_read and (len(signal.values) >= sample_counter):
                    continue

                if last_server_id != signal.serverid:
                    last_server_id = signal.serverid
                    doip_client.change_ecu_logical_address(signal.serverid)

                if print_results:
                    print("\rSample {2}/{3}: Reading did 0x{1:04x} for server 0x{0:04x} - {4}/{5}  "
                            .format(signal.serverid, signal.did.did, sample_counter, num_samples_name, signal_counter, signals_total_num), end="")

                # Suppress lower-level messages
                if activate_logging_flag:
                    logging.getLogger().setLevel(logging.WARNING)

                # Establish a client to read data by identifier
                try:
                    with Client(conn, request_timeout=timeout) as client:
                        response = client.read_data_by_identifier_first(didlist=[signal.did.did])
                        signal.values.append(Value(time=datetime.datetime.now(), value=response))
                except Exception as e:
                    print(f"An issue occurred while probing DID 0x{signal.did.did:04x} for server 0x{signal.serverid:04x}: {e}")
                    if activate_logging_flag:
                        logging.warning(f"An issue occurred while probing DID 0x{signal.did.did:04x} for server 0x{signal.serverid:04x}: {e}")

                # Acitvate lower-level messages again
                if activate_logging_flag:
                    logging.getLogger().setLevel(logging.INFO)      

    except KeyboardInterrupt:
        end_time = time.time()
        total_time = end_time - start_time
        experiment.experiment_runtime_seconds += total_time
        print(f"\nRead data interrupted. Time elapsed: {experiment.experiment_runtime_seconds} seconds.")
        return experiment

    end_time = time.time()
    total_time = end_time - start_time
    experiment.experiment_runtime_seconds += total_time
    print(f"\nRead data completed. Time elapsed: {round(total_time, 3)} seconds.")
    print(f"Number of cycles: {num_samples}")
    frequency = num_samples / total_time
    if frequency > 0.1:
        frequency = round(frequency, 2)
    print(f"Frequency: {frequency} Hz")
    if activate_logging_flag:
        logging.info(f"\nRead data completed. Time elapsed: {round(total_time, 3)} seconds.")
        logging.info(f"Number of cycles: {num_samples}")
        logging.info(f"Frequency: {frequency} Hz")
    return experiment


def __read_data_wrapper(config_file_path, 
                        experiment_file_path,
                        num_samples, 
                        activate_logging_flag, 
                        reset_experiment:bool=False,
                        continue_read:bool=False):
    """
       Wrapper function used read data as defined in an experiment.

       Args:
           config_file_path (str): Path to the configuration file.
           experiment_file_path (str): Path to the experiment defintion file.
           activate_logging_flag: activate logging
       """
    # Load config
    config = Config(config_file_path)
    doip_config = config.get("doip")

    # Try to load experiment
    try:
        experiment = Experiment.load(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading experiment model: {e}")
        return

    # Try to save experiment
    try:
        experiment.save(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving experiment model: {e}")
        return

    # Reset Experiment if flag is set
    if reset_experiment:
        for signal in experiment.measurements:
            signal.values = []
        for measurement in experiment.external_measurements:
            measurement.values = []
        experiment.experiment_runtime_seconds = 0.0
        try:
            experiment.save(experiment_file_path)
        except FileNotFoundError:
            print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
            return
        except Exception as e:
            print(f"Error saving experiment model: {e}")
            return
        print(f"Successfully deleted all values.")
        return


    # Setup Logging if flag is set
    if activate_logging_flag:
        logging_file_path = os.path.dirname(experiment_file_path) + '/logging/'
        experiment_file_name = os.path.splitext(os.path.basename(experiment_file_path))[0]
        if not os.path.exists(logging_file_path):
            os.makedirs(logging_file_path)
        logging.basicConfig(
            filename=logging_file_path + experiment_file_name + '_read-data.log',
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

    # client_logical_address = car.client_logical_address
    client_logical_address = experiment.car.arb_id_pairs[0].client_logical_address

    if client_logical_address is None:
        print("arb_id_response not found in the configuration.")
        return

    timeout = doip_config.get("service_discovery_timeout")
    ecu_ip_address = config.get(f"vehicles.{experiment.car.model}_{experiment.car.vin}_ip_address")


    # Probe dids
    experiment = read_data(     experiment=experiment,
                                client_logical_address=client_logical_address,
                                ecu_ip_address=ecu_ip_address,
                                num_samples=num_samples,
                                timeout=timeout,
                                print_results=True,
                                activate_logging_flag=activate_logging_flag,
                                continue_read=continue_read)


    try:
        experiment.save(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        if activate_logging_flag:
            logging.warning(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving experiment model: {e}")
        if activate_logging_flag:
            logging.warning(f"Error saving experiment model: {e}")
        return

    pass


if __name__ == "__main__":
    # Parse command-line arguments for configuration and experiment model paths
    argparser = argparse.ArgumentParser(
        description="Read data as defined in the experiment file"
    )
    argparser.add_argument(
        "--config_file_path",
        dest="config_file_path",
        type=str,
        help="Path to config file",
    )
    argparser.add_argument(
        "--experiment_file_path",
        dest="experiment_file_path",
        type=str,
        help="Path to experiment file",
    )
    argparser.add_argument(
        "--num_samples",
        dest="num_samples",
        type=int,
        help="Number of values to read per signal. Default = 1; Infinity = -1",
    )
    argparser.add_argument(
        "--activate_logging_flag",
        dest="activate_logging_flag",
        type=bool,
        help="Flag that indicates whether to log the progress of the did discovery",
    )
    argparser.add_argument(
        "--reset_experiment",
        dest="reset_experiment",
        type=bool,
        help="Flag that indicates whether to delete all existing measurements",
    )
    argparser.add_argument(
        "--continue_read",
        dest="continue_read",
        type=bool,
        help="Flag that indicates whether to continue the latest measurements",
    )
    

    args = argparser.parse_args()

    __read_data_wrapper(args.config_file_path, 
                        args.experiment_file_path, 
                        args.num_samples, 
                        args.activate_logging_flag, 
                        args.reset_experiment,
                        args.continue_read )