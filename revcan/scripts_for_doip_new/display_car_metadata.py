import argparse
from revcan.reverse_engineering.models.car_metadata import Car
import datetime

def display_car_vin(car: Car):
    print(f"Car Vin: {car.vin}")

def display_car_model(car: Car):
    print(f"Car Model: {car.model}")

def display_number_of_services(car: Car):
    print(f"Number of Services found: {len(car.services)}")

def display_number_of_servers(car: Car):
    print(f"Number of Servers found: {len(car.servers)}")

def display_total_number_of_dids(car: Car):
    total_number_of_dids = 0
    for server in car.servers:
        total_number_of_dids += len(server.parameters)
    print(f"Total Number of DIDs found: {total_number_of_dids}")

def display_server_discovery_complete(car: Car, max_server_id: int = 65535):
    print(f"Server Discovery complete: {max_server_id < car.first_unchecked_server_id_in_server_discovery}")
    if car.first_unchecked_server_id_in_server_discovery == 0:
        print(f"Server Discovery not started. Total number of possible Server IDs: {max_server_id}")
    elif max_server_id >= car.first_unchecked_server_id_in_server_discovery:
        print(f"Last checked Server ID: {car.first_unchecked_server_id_in_server_discovery-1}/{max_server_id}")

def display_total_time_server_discovery(car: Car):
    print(f"Total Time Server Discovery: {str(datetime.timedelta(seconds=car.server_discovery_time_seconds))}")

def display_total_time_did_discovery(car: Car):
    total_time_did_discovery = 0
    for server in car.servers:
        total_time_did_discovery += server.did_discovery_time_seconds
    print(f"Total Time DID Discovery: {str(datetime.timedelta(seconds=total_time_did_discovery))}")

def display_average_time_did_discovery(car: Car, max_did: int = 65535):
    total_time_did_discovery = 0
    number_of_timed_servers = 0
    for server in car.servers:
        if server.did_discovery_time_seconds > 0:
            total_time_did_discovery += server.did_discovery_time_seconds
            number_of_timed_servers += 1
            
    if number_of_timed_servers != 0:
        average_time_did_discovery_per_server = total_time_did_discovery / number_of_timed_servers
    else:
        average_time_did_discovery_per_server = 0.0

    print(f"Average Time DID Discovery per Server: {str(datetime.timedelta(seconds=int(average_time_did_discovery_per_server)))}")

def display_forecast_remaining_time_server_discovery(car: Car, min_server_id: int = 0, max_server_id: int = 65535):
    if car.first_unchecked_server_id_in_server_discovery <= max_server_id and car.first_unchecked_server_id_in_server_discovery > min_server_id:
        forecast_remaining_time_server_discovery = (car.server_discovery_time_seconds / (car.first_unchecked_server_id_in_server_discovery - min_server_id)) * (max_server_id - car.first_unchecked_server_id_in_server_discovery + 1)
    elif car.first_unchecked_server_id_in_server_discovery > max_server_id:
        forecast_remaining_time_server_discovery = 0
    else:
        forecast_remaining_time_server_discovery = None

    if forecast_remaining_time_server_discovery == None:
        print(f"Server Discovery not started - Cannot give Estimate/Forecast for Remaining Time Needed for Server Discovery")
    else:
        print(f"Forecast/Estimate - Remaining Time Needed for Server Discovery: ≈ {str(datetime.timedelta(seconds=int(forecast_remaining_time_server_discovery)))}")

def display_forecast_remaining_time_did_discovery(car: Car, max_did: int = 65535):
    total_time_did_discovery = 0
    number_of_timed_servers = 0
    number_of_unfinished_servers = 0.0
    for server in car.servers:
        if server.did_discovery_time_seconds > 0:
            total_time_did_discovery += server.did_discovery_time_seconds
            number_of_timed_servers += 1
        number_of_unfinished_servers += 1.0 - ((server.first_unchecked_did_in_did_discovery - 1) / max_did)

    print(f"Number of Servers with unfinished DID discovery: {number_of_unfinished_servers:.2f} / {len(car.servers)}")
    if number_of_timed_servers == 0:
        print(f"DID Discovery not finished for any server - Cannot give Estimate/Forecast for Remaining Time Needed for DID Discovery")
    else:
        average_time_did_discovery_per_server = total_time_did_discovery / number_of_timed_servers
        print(f"Forecast/Estimate - Remaining Time Needed for DID Discovery: ≈ {str(datetime.timedelta(seconds=int(average_time_did_discovery_per_server*number_of_unfinished_servers)))}")

def display_services_table(car: Car):
    numCharactersId = 4
    numCharactersName = 50
    print("\nServices Table:")
    print(f"{'ID':>{numCharactersId}} | {'Name':<{numCharactersName}}")
    print(f"{'-'*(numCharactersId+1):>{numCharactersId}}|{'-'*numCharactersName:<{numCharactersName}}")
    for service in car.services:
        print(f"{service.id:>{numCharactersId}} | {service.name:<{numCharactersName}}")
    print(f"{'-'*(numCharactersId+numCharactersName+2)}")

def display_servers_table(car: Car, max_did: int = 65535):
    numCharactersIdDecimal = 7
    numCharactersIdHex = 7
    numCharactersParameters = 15
    numCharactersDiscoveryTime = 15
    numCharactersCompleteFlag = 25
    print("\nServer Table:")
    print(f"{'ID₁₀':>{numCharactersIdDecimal}} | {'ID₁₆':>{numCharactersIdHex}} | {'Number of DIDs':>{numCharactersParameters}} | {'Discovery Time':>{numCharactersDiscoveryTime}} | {'DID Discovery Complete':>{numCharactersCompleteFlag}}")
    print(f"{'-'*(numCharactersIdDecimal):>{numCharactersIdDecimal}} | {'-'*(numCharactersIdHex):>{numCharactersIdHex}} | {'-'*(numCharactersParameters):>{numCharactersParameters}} | {'-'*(numCharactersDiscoveryTime):>{numCharactersDiscoveryTime}} | {'-'*(numCharactersCompleteFlag):>{numCharactersCompleteFlag}}")
    for server in car.servers:
        if server.first_unchecked_did_in_did_discovery > 0:
            completeness_percentage = f"{(((server.first_unchecked_did_in_did_discovery - 1) / max_did) * 100):.2f} %"
        else:
            completeness_percentage = ""
        if server.did_discovery_time_seconds > 0:
            discovery_time = str(datetime.timedelta(seconds=server.did_discovery_time_seconds))
        else:
            discovery_time = ''
        if len(server.parameters) > 0:
            number_of_parameters = len(server.parameters)
        else:
            number_of_parameters = ""
        print(f"{server.id:>{numCharactersIdDecimal}} | {hex(server.id):>{numCharactersIdHex}} | {number_of_parameters:>{numCharactersParameters}} | {discovery_time:>{numCharactersDiscoveryTime}} | {completeness_percentage:>{numCharactersCompleteFlag}}")
    print(f"{'-'*(numCharactersIdDecimal+numCharactersIdHex+numCharactersParameters+numCharactersDiscoveryTime+numCharactersCompleteFlag+12)}")

def display_car_metadata(car: Car, max_id: int = 65535):
    # Display the metadata of the provided car
    print("\n")
    display_car_model(car)
    display_car_vin(car)
    display_number_of_services(car)
    display_number_of_servers(car)
    display_total_number_of_dids(car)
    display_server_discovery_complete(car, max_id)
    display_total_time_server_discovery(car)
    display_total_time_did_discovery(car)
    display_average_time_did_discovery(car)
    display_forecast_remaining_time_server_discovery(car)
    display_forecast_remaining_time_did_discovery(car)
    print("\n")
    display_services_table(car)
    print("\n")
    display_servers_table(car)

def __display_car_metadata_wrapper(car_model_file_path: str, max_id: int = 65535):
    # Try to load car_model_path
    try:
        car = Car.load(car_model_file_path)
    except FileNotFoundError:
        print(f"Error: The car model file at '{car_model_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading car model: {e}")
        return
    
    display_car_metadata(car, max_id)

if __name__ == "__main__":
    # Parse command-line arguments for configuration and car model paths
    argparser = argparse.ArgumentParser(
        description="Display Metadata of provided car file"
    )
    argparser.add_argument(
        "--car_model_path",
        dest="car_model_path",
        type=str,
        help="Path to car model",
    )
    args = argparser.parse_args()

    __display_car_metadata_wrapper(args.car_model_path)