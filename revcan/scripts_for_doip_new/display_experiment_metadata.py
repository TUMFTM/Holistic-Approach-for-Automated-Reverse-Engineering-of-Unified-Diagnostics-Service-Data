import argparse
from revcan.reverse_engineering.models.experiment import Experiment
import datetime

def display_experiment_name(experiment: Experiment):
    print(f"Name: {experiment.name}")

def display_experiment_description(experiment: Experiment):
    print(f"Description: {experiment.description}")

def display_experiment_starttime(experiment: Experiment):
    print(f"Starttime: {experiment.starttime}")

def display_experiment_value_metadata(experiment: Experiment):
    experiment_runtime_seconds = experiment.experiment_runtime_seconds
    if experiment.measurements:
        number_of_values_per_signal = len(experiment.measurements[-1].values)
        if number_of_values_per_signal > 0:
            average_experiment_runtime_seconds = experiment_runtime_seconds / number_of_values_per_signal
        else:
            average_experiment_runtime_seconds = 0
    else:
        number_of_values_per_signal = 0
        average_experiment_runtime_seconds = 0
    
    # print(f"Runtime: {str(datetime.timedelta(seconds=experiment.experiment_runtime_seconds))}")
    print(f"Number of Samples: {number_of_values_per_signal}")
    print(f"Runtime: {str(datetime.timedelta(seconds=experiment_runtime_seconds))}")
    print(f"Average runtime per Sample: {str(datetime.timedelta(seconds=average_experiment_runtime_seconds))}")

def display_number_of_signals(experiment: Experiment):
    print(f"Number of Signals in Experiment: {len(experiment.measurements)}")

def display_number_of_ground_truth_values(experiment: Experiment):
    if experiment.external_measurements:
        number_of_external_measurements = len(experiment.external_measurements[0].values)
    else:
        number_of_external_measurements = 0

    if experiment.external_alphanumeric_measurements:
        number_of_external_alphanumeric_measurements = len(experiment.external_alphanumeric_measurements[0].values)
    else:
        number_of_external_alphanumeric_measurements = 0
    print(f"Number of External Measurements: {number_of_external_measurements}")
    print(f"Number of External Alphanumeric Measurements: {number_of_external_alphanumeric_measurements}")

def __display_experiment_metadata_wrapper(experiment_file_path: str, max_server_id: int = 65535):
    # Try to load experiment_file_path
    try:
        experiment = Experiment.load(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading experiment: {e}")
        return
    
    # Display the metadata of the provided experiment
    print("\n")
    display_experiment_name(experiment)
    display_experiment_description(experiment)
    display_experiment_starttime(experiment)
    display_experiment_value_metadata(experiment)
    display_number_of_signals(experiment)
    display_number_of_ground_truth_values(experiment)
    print("\n")

if __name__ == "__main__":
    # Parse command-line arguments for configuration and car model paths
    argparser = argparse.ArgumentParser(
        description="Display Metadata of provided car file"
    )
    argparser.add_argument(
        "--experiment_file_path",
        dest="experiment_file_path",
        type=str,
        help="Path to experiment file",
    )
    args = argparser.parse_args()

    __display_experiment_metadata_wrapper(args.experiment_file_path)