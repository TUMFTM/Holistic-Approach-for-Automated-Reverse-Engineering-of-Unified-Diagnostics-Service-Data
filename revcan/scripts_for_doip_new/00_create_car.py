import argparse
import os
from datetime import date

from revcan.reverse_engineering.models.car_metadata import Car

def create_Car(vin="", 
               model="", 
               file_path="~/data/car_metadata", 
               file_suffix=""):
    car = Car.create_empty_Car()
    car.vin = vin
    car.model = model

    if vin:
        vin_name = vin
    else:
        vin_name = "UNKNOWN-VIN"

    if model:
        model_name = model
    else:
        model_name = "UNKNOWN-MODEL"

    if file_suffix is None:
        file_suffix = ""

    if file_path is None:
        file_path="./data/car_metadata"
    file_path = os.path.expanduser(file_path)

    file_name = model_name + "_" + vin_name + "_" + date.today().strftime("%Y-%m-%d") + file_suffix + ".json"
    file_name = file_name.replace(" ", "_")

    if file_path[-1] != '/':
        file_path  = file_path + "/"

    car_model_file_path = file_path + file_name

    # Check if file with that specific name already exists at specified destination
    if os.path.exists(car_model_file_path):
            print("\rERROR: Unable to save file {2}: There already exists a file named {0} at destination {1}."
                            .format(file_name, file_path, car_model_file_path), end="")
            return
    else:
        print("\rTrying to create new file {0} at destination {1}:\n"
                            .format(file_name, file_path, car_model_file_path), end="")

    try:
        car.save(car_model_file_path)
        print("Successful")
    except Exception as e:
        print(f"Error saving car model: {e}")
        return


if __name__ == "__main__":
    # Parse command-line arguments for configuration and car model paths
    argparser = argparse.ArgumentParser(
        description="Create a new car file with name vin_"
    )
    argparser.add_argument(
        "--vin",
        dest="vin",
        type=str,
        help="Vin of the car",
    )
    argparser.add_argument(
        "--model",
        dest="model",
        type=str,
        help="Model of the car",
    )
    argparser.add_argument(
        "--file_path",
        dest="file_path",
        type=str,
        help="Path to destination were the new car file should be saved",
    )
    argparser.add_argument(
        "--file_suffix",
        dest="file_suffix",
        type=str,
        help="The suffix that should be added to the file",
    )
    args = argparser.parse_args()

    create_Car(args.vin, args.model, args.file_path, args.file_suffix)