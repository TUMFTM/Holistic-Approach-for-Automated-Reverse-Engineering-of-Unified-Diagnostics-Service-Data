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

def filter_signals_by_bitflip_rate(experiment: Experiment,
                          keep_values_flag: bool,
                          absolute_number_of_samples = -1,
                          relative_number_of_samples = 0.5,
                          print_results=True,
                          activate_logging_flag=False,
                          ):


    total_bit_flips = 0
    total_bit_comparisons = 0

    for i in range(len(measurements) - 1):
        # Compute the bitwise XOR of two integers to find differing bits.
        xor_result = measurements[i] ^ measurements[i + 1]
        # Count the number of differing bits (Hamming distance).
        bit_flips = bin(xor_result).count('1')
        total_bit_flips += bit_flips
        # Total bit comparisons = number of bits in the binary representation
        # of the largest number encountered.
        total_bit_comparisons += max(measurements[i].bit_length(), measurements[i + 1].bit_length())

    # Calculate the flip rate as the total bit flips divided by total bit comparisons.
    flip_rate = total_bit_flips / total_bit_comparisons if total_bit_comparisons > 0 else 0.0

    return flip_rate



def keep_constant_signals(experiment: Experiment,
                          keep_values_flag: bool,
                          minimum_number_of_values=2,
                          print_results=True,
                          activate_logging_flag=False,
                          ):
    signals_to_be_removed = []

    for signal in experiment.measurements:
        # Check if at least minimum_number_of_values are present
        if len(signal.values) >= minimum_number_of_values:
            keep_current_signal = True
            for i in range(len(signal.values) - 1):
                if signal.values[i] != signal.values[i + 1]:
                    keep_current_signal = False
                    break
            if keep_current_signal == True:
                # Keep signal
                if not keep_values_flag:
                    signal.values = []
                pass
            else:
                #elements from the list which is currently being itterated should be removed later
                signals_to_be_removed.append(signal)
                pass


        else:
            print(f'Error: Less than {minimum_number_of_values} values for did {signal.did} on server {signal.server}.')
            if activate_logging_flag:
                logging.warning(f'Error: Less than two values for did {signal.did} on server {signal.server}.')

    for signal in signals_to_be_removed:
        experiment.measurements.remove(signal)

    return experiment


def keep_non_constant_signals(experiment: Experiment,
                            keep_values_flag: bool,
                            minimum_number_of_values=2,
                            print_results=True,
                            activate_logging_flag=False,
                              ):
    signals_to_be_removed = []

    for signal in experiment.measurements:
        # Check if at least minimum_number_of_values are present
        if len(signal.values) >= minimum_number_of_values:
            keep_current_signal = True
            for i in range(len(signal.values) - 1):
                if signal.values[i] == signal.values[i + 1]:
                    keep_current_signal = False
                    break
            if keep_current_signal == True:
                # Keep signal
                if not keep_values_flag:
                    signal.values = []
                pass
            else:
                # elements from the list which is currently being itterated should be removed later
                signals_to_be_removed.append(signal)
                pass


        else:
            print(f'Error: Less than {minimum_number_of_values} values for did {signal.did} on server {signal.server}.')
            if activate_logging_flag:
                logging.warning(f'Error: Less than two values for did {signal.did} on server {signal.server}.')

    for signal in signals_to_be_removed:
        experiment.measurements.remove(signal)

    return experiment


def filter_experiment(experiment: Experiment,
                      filter_name: str,
                      keep_values_flag: bool,
                      print_results=True,
                      activate_logging_flag=False,
                      ):
    if filter_name == 'constant':
        return keep_constant_signals(experiment=experiment,
                                     keep_measurements_flag=keep_values_flag,
                                     print_results=print_results,
                                     activate_logging_flag=activate_logging_flag)
    elif filter_name == 'non-constant':
        return keep_non_constant_signals(experiment=experiment,
                                         keep_measurements_flag=keep_values_flag,
                                         print_results=print_results,
                                         activate_logging_flag=activate_logging_flag)
    else:
        print(
            f'The provided filter_name {filter_name} is unknown. Please select one of these possible values: constant, non-constant')
        if activate_logging_flag:
            logging.warning(
                f'The provided filter_name {filter_name} is unknown. Please select one of these possible values: constant, non-constant')

    return experiment


def filter_experiment_wrapper(experiment_file_path, filter_name:str, experiment_output_file_path, keep_values_flag:bool,
                              activate_logging_flag):
    """
       Wrapper function used filter the dids for an experiment.

       Args:
           experiment_file_path (str): Path to the experiment defintion file.
           filter_name (str): Name of the filter that shall be applied
           experiment_output_file_path (str): Path where the filtered Experiment shall be store
           keep_values_flag (bool): If set to False, all previous measured values will be deleted, generating a clean experiment
           activate_logging_flag: activate logging
       """

    # Try to load input experiment
    try:
        experiment = Experiment.load(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading experiment model: {e}")
        return

    # Try to save output experiment
    try:
        experiment.save(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving experiment model: {e}")
        return

    # Setup Logging if flag is set
    if activate_logging_flag:
        logging_file_path = os.path.dirname(experiment_file_path) + '/logging/'
        experiment_file_name = os.path.splitext(os.path.basename(experiment_file_path))[0]
        if not os.path.exists(logging_file_path):
            os.makedirs(logging_file_path)
        logging.basicConfig(
            filename=logging_file_path + experiment_file_name + '_filter-experiment.log',
            filemode='a',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )

    experiment = filter_experiment(experiment=experiment,
                                   filter_name=filter_name,
                                   keep_values_flag=keep_values_flag,
                                   activate_logging_flag=activate_logging_flag)

    if not os.path.exists(experiment_output_file_path):
        os.makedirs(experiment_output_file_path)
    try:
        experiment.save(experiment_output_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_output_file_path}' was not found.")
        if activate_logging_flag:
            logging.warning(f"Error: The experiment model file at '{experiment_output_file_path}' was not found.")
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
        description="Creates a new experiment with the selected filter applied"
    )
    argparser.add_argument(
        "--experiment_file_path",
        dest="experiment_file_path",
        type=str,
        help="Path to experiment file",
    )
    argparser.add_argument(
        "--filter_name",
        dest="filter_name",
        type=str,
        help="Name of the filter that should be applied. Possible values: 'constant', 'non-constant'",
    )
    argparser.add_argument(
        "--experiment_output_file_path",
        dest="experiment_output_file_path",
        type=bool,
        help="Path to experiment output file",

    )

    argparser.add_argument(
        "--keep_values_flag",
        dest="keep_values_flag",
        type=bool,
        help="Flag that indicates whether to keep the measurements of the input experiment",
        default=True,
    )

    argparser.add_argument(
        "--activate_logging_flag",
        dest="activate_logging_flag",
        type=bool,
        help="Flag that indicates whether to log the progress of the did discovery",
    )

    args = argparser.parse_args()

    __filter_experiment_wrapper(args.experiment_file_path, args.filter_name, args.experiment_output_file_path,
                                args.keep_values_flag, args.activate_logging_flag)
