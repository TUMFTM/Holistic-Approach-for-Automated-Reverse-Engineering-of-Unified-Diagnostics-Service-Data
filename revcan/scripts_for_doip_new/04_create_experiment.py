import argparse

from revcan.reverse_engineering.models import car_metadata
from revcan.reverse_engineering.models.experiment import Experiment, Signal


def create_experiment(car_model_file_path, 
                      experiment_file_path, 
                      experiment_name, 
                      experiment_description, 
                      signal_selection):

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

    experiment = Experiment.create_empty_experiment()


    experiment.name = experiment_name
    experiment.description = experiment_description
    experiment.car = car

    if signal_selection == "none":
        experiment.measurements = []
    elif signal_selection == "all":
        for server in experiment.car.servers:
            for parameter in server.parameters:
                experiment.measurements.append(Signal(serverid = server.id, did = parameter, values = []))
    else:
        experiment.measurements = []

    try:
        experiment.save(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The path to '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error saving experiment model: {e}")
        return
    #measurements: List[Signal]


if __name__ == "__main__":
    # Parse command-line arguments for configuration and experiment model paths
    argparser = argparse.ArgumentParser(
        description="Creates an experiment from a car model file, with all servers and dids"
    )
    argparser.add_argument(
        "--car_model_file_path",
        dest="car_model_file_path",
        type=str,
        help="Path to car model",
    )
    argparser.add_argument(
        "--experiment_file_path",
        dest="experiment_file_path",
        type=str,
        help="Path to experiment file",
    )
    argparser.add_argument(
        "--experiment_name",
        dest="experiment_name",
        type=str,
        help="Name of the experiment",
    )
    argparser.add_argument(
        "--experiment_description",
        dest="experiment_description",
        type=str,
        help="Description of the experiment",
    )
    argparser.add_argument(
        "--signal_selection",
        dest="signal_selection",
        type=str,
        help="Select the signals that should be included. Possible values: 'all', 'none' ",
    )

    args = argparser.parse_args()

    create_experiment(args.car_model_file_path, args.experiment_file_path, args.experiment_name, args.experiment_description, args.signal_selection)
