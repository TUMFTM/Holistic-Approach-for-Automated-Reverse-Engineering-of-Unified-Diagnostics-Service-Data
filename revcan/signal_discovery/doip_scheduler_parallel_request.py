"""
This module defines the class Scheduler for managing and scheduling requests.
It handles loading and saving requests, executing requests in subsets, and maintaining scheduling-related attributes.
"""

from revcan.signal_discovery.doip_dids import (
    DoIPDidRequest,
    RequestList,
    DidRequestDatabase,
    DoIPConnector,
)
from utils.network_actions import NetworkActions
from utils.udsoncan.client import Client as UDSClient
from utils.udsoncan import services, Request, Response
from utils.udsoncan.ResponseCode import ResponseCode
import revcan.signal_discovery.utils.misc_methods as misc
from io import BufferedWriter
from collections import defaultdict
import threading
import time
import math
import random
import os
import csv
import pickle
import pyshark
import logging
import asyncio
from typing import Union
import logging


class ParallelScheduler:
    """
    A class for scheduling and managing requests.

    Attributes:
    - request_list: A list of requests to be scheduled.
    - subset_lists: A list of subsets of the requests in case there are too many requests to be processed at once.
    - buffer_list: A buffer for holding requests before execution.
    - added_to_buffer: A set to track unique IDs of requests added to the buffer.
    - theoretical_loop_time: The estimated time it takes to loop through the list of requests.
    - average_request_time: The average time taken by a request.
    - script_directory: The directory of the script containing this class.
    - create_output_csv: Flag indicating whether to create an output CSV file.
    - csv_filepath: Absolute filepath to the CSV file for output.
    - ignore_blacklisted_requests: Flag to ignore blacklisted requests during scheduling.
    - wait_window_request: Time to wait for a response.
    - random: Flag for random request processing.
    - print_info: Flag for printing debugging information.
    - iterations: Number of iterations for the scheduling process.
    - end_time: The end time for scheduling.
    - average: The average execution time for one loop of all requests.
    - remaining_time: Remaining time for the initial request process.
    - iteration_counter: Counter for scheduling iterations.
    - subset_payload_for_csv: Payload list for CSV during debugging in random mode.

    Methods:
    - __init__: Initializes the Scheduler instance.
    - __str__: Returns the string representation of the Scheduler instance.
    - load_requests: Loads requests from a specified path.
    - save_data: Saves the request data to a database and optionally exports as CSV.
    - request_all: Executes requests for the entire request list once.
    - populate_history: Populates the history of requests using the request_all method.
    - check_if_subsets_necessary: Checks if subsets are necessary based on request count.
    - split_request_list: Splits the request list into subsets if necessary.
    - start: Starts the scheduling process with options for subsets and iterations.
    - update: Updates buffer_list during execution by comparing, when a request was executed last.
    - add_requests_to_buffer: Adds requests to the buffer if certain conditions are met.
    - append_debug_history: Appends debug information of the request to the debug history.
    - adjust_for_max_requests: Adjusts intervals to meet max requests requirement.
    - calculate_send_count: Calculates the number of requests that could be sent during the average loop time.
    - request: Main method for executing requests in a separate thread.
    - append_to_output_csv: Appends results to the output CSV file.
    """

    current_request_dict = {}  # Dictionary of requests
    requesters = []  # List of Requester instances
    evaluators = []  # List of Evaluator instances
    capture_dict = {}  # List of distributed responses
    capture_list = []  # List of captured responses

    def __init__(self, interface: str, number_of_requesters: int):
        """
        Initializes the Scheduler instance.
        """
        self.parallel = False
        self.request_list: RequestList = RequestList()
        self.subset_lists: list[RequestList] = []
        self.buffer_list: list[DoIPDidRequest] = []
        self.interface = interface
        self.number_of_requesters = number_of_requesters
        self.connection = NetworkActions(
            self.interface
        )  # initiates a connection to the vehicle using the ethernet interface of the computer
        self.doip_connector: DoIPConnector = DoIPConnector()  # type: ignore
        self.added_to_buffer = set()
        self.theoretical_loop_time: int
        self.average_request_time: float = 0
        self.script_directory = os.path.dirname(__file__)
        self.create_output_csv = False
        self.csv_filepath = None  # Absolute filepath to csv file
        self.ignore_blacklisted_requests = True
        self.wait_window_request = 0.5
        self.random = False
        self.print_info: bool = False
        self.iterations = 10
        self.end_time = 0
        self.average = 0
        self.remaining_time = 0
        self.iteration_counter = 0
        self.subset_payload_for_csv = (
            []
        )  # Explanation: while Debugging the GUI in the random-Mode at some point during the Recording the csv.-file couldnt be writen to anymor (Errno 13: Permission denied), after long testing the bug couldn't be found so the GUI first saves the Recording Data to the list, which is then writen to the csv.-file

        # Preparations for threads
        # self.request_thread = threading.Thread(target=self.request)
        self.end_request_thread = False
        # self.update_thread = threading.Thread(target=self.update)

    def __str__(self):
        """
        Returns the string representation of the DidList instance.

        :return: a list of all elements
        :rtype: str
        """
        output = ""
        for did in self.request_list.request_list:
            output += str(did) + "\n"
        return output

    def load_requests(self, path, maximum_payload_length=-1, want_payload_history=True):
        """
        Loads requests from a specified path.

        :param path: The path to the requests.
        :type path: str

        :raises ValueError: If no requests are loaded.
        """
        if maximum_payload_length > 0:
            self.maximum_payload_length = maximum_payload_length
        else:
            self.maximum_payload_length = None

        load_path = os.path.join(self.script_directory, path)
        print(load_path)

        if load_path[-3:] == ".db":
            print("DB File")
            self.request_list.fill_request_list_from_single_database_file(
                load_path, want_payload_history
            )
        else:
            print("Directory")
            self.request_list.fill_request_list_from_database_files(
                load_path, want_payload_history
            )
        if len(self.request_list.request_list) == 0:
            raise ValueError(
                "No requests have been loaded. Either the directory does not contain database files or the database files are empty."
            )
        if self.maximum_payload_length:
            # remove requests with too long payload
            self.request_list.request_list = [
                request
                for request in self.request_list.request_list
                if not request.history.payload_list
                or len(request.history.payload_list[0]) <= self.maximum_payload_length
            ]
        print(f"Length of request_list {len(self.request_list.request_list)}")

    def save_data(self, folder, save_name, export_csv=False):
        """
        Saves the request data to a database and optionally exports as CSV.

        :param save_name: The name for the saved database.
        :type save_name: str

        :param export_csv: Flag indicating whether to export as CSV.
        :type export_csv: bool
        """

        save_string = folder + save_name + ".db"
        with DidRequestDatabase(save_string) as database:
            database.reset_database()
            database.store_list(self.request_list.request_list)
            if export_csv:
                database.export_db_as_csv()

    def set_up_dict_req_eval(
        self,
        number_of_requesters: int,
        interface: str,
        csv_file_path: Union[str, None] = None,
    ):
        # set up current_request_dict and create Requester instances
        self.create_current_request_dict(number_of_requesters)
        self.create_requesters(number_of_requesters)
        self.create_evaluators(
            number_of_requesters, interface, csv_file_path, self.wait_window_request
        )
        self.set_up_capture_dict(self.number_of_requesters)

    @classmethod
    def get_current_requested_server(cls):
        server_ids = []
        for key, value in cls.current_request_dict.items():
            if value["List"] is not None:
                if isinstance(value["List"], list):
                    try:
                        server_ids.append(value["List"][0].ids.server_id)
                    except:
                        pass
                else:
                    server_ids.append(value["List"].ids.server_id)
        return server_ids

    def request_all(self):
        """
        Executes requests for the entire request list once.
        """
        sent_requests = 0
        elapsed_time = []
        request_list_copy = self.request_list.request_list.copy()

        if self.parallel:  # Wenn parallel True ist, Anfragen parallel senden

            while not self.capture_active:
                time.sleep(0.1)  # Sleep for a short duration to avoid busy waiting
                # to wait for the capture thread to start
                # should be activated only at fist iteration of the request_all method

            start = time.time()

            while request_list_copy:
                requests_to_send = []
                payload_length = 0
                server_ids = self.get_current_requested_server()
                for request in request_list_copy:
                    if (
                        requests_to_send == []
                    ):  # if requests_to_send is empty, add the first request to the list
                        if request.ids.server_id not in server_ids:
                            requests_to_send.append(request)
                            payload_length += request.ids.payload_length
                            if self.performance_dict:
                                try:
                                    max_did = self.performance_dict[
                                        request.ids.server_id
                                    ]["DID_length"]
                                    max_payload = self.performance_dict[
                                        request.ids.server_id
                                    ]["Payload_length"]
                                except:
                                    max_did = self.dids_in_request
                            else:
                                max_did = self.dids_in_request
                            continue
                        else:
                            continue

                    if request.ids.server_id == requests_to_send[0].ids.server_id:
                        requests_to_send.append(request)
                        payload_length += request.ids.payload_length
                        if max_payload and (
                            payload_length > max_payload
                        ):  # if the payload length is too long, stop adding requests and remove last entry
                            requests_to_send.pop()
                            break

                        if (
                            len(requests_to_send) == max_did
                        ):  # if the maximum number of DIDs is reached, stop adding requests
                            break

                for request in requests_to_send:
                    sent_requests += 1
                    request_list_copy.remove(
                        request
                    )  # remove the requests from the request_list_copy

                if self.print_info:
                    print(
                        "Sending requests:",
                        [did.ids.did for did in requests_to_send],
                    )

                self.send_request(requests_to_send)  # Die gesammelten Anfragen senden

                left = len(request_list_copy)
                elapsed = time.time() - start
                elapsed_time.append(elapsed)
                self.average = round(elapsed / sent_requests, 3)
                target_time = time.time() + (self.average) * left
                self.remaining_time = int(target_time - time.time())
                target_time = time.strftime("%T", time.localtime(target_time))
                current_time = time.strftime("%T", time.localtime(time.time()))
                print(
                    f"\r Current time: {current_time}, Target time: {target_time}, Remaining: {self.remaining_time}s, Left: {left}, Average request time: {self.average}",
                    end="",
                )

        else:
            for i, request in enumerate(self.request_list.request_list):
                start = time.time()
                if self.random:
                    request.get_rnd_value()
                else:
                    request.get_value(self.wait_window_request)
                left = len(self.request_list.request_list) - i
                elapsed = time.time() - start
                elapsed_time.append(elapsed)
                self.average = round(sum(elapsed_time) / len(elapsed_time), 3)
                target_time = time.time() + (self.average * left)
                self.remaining_time = int(target_time - time.time())
                target_time = time.strftime("%T", time.localtime(target_time))
                current_time = time.strftime("%T", time.localtime(time.time()))
                print(
                    f"\rCurrent time: {current_time}, Target time: {target_time}, Remaining: {self.remaining_time}s, Left: {left}, Average request time: {self.average}",
                    end="",
                )

    def start_capture_distribute_threads(self, server_id, tester_id):
        self.capture_is_active = True
        self.distribute_active = True
        self.capture_thread = threading.Thread(
            target=self.capture_task,
            args=(server_id, tester_id, self.wait_window_request),
        )
        self.response_distribution_thread = threading.Thread(
            target=self.distribute_responses
        )
        self.capture_active = False
        self.response_distribution_thread.start()
        self.capture_thread.start()

    def stop_capture_distribute_threads(self):
        self.capture_is_active = False
        self.distribute_active = False
        self.capture_thread.join()
        self.response_distribution_thread.join()

    def populate_history(
        self,
        wait_window,
        iterations=10,
        random=False,
        GUI_mode=False,
        dids_in_request=1,
        csv_filepath=None,
        performance_list=None,
        ignore_blacklisted_requests=False,
    ):
        """
        Populates the history of requests using the request_all method.

        :param interval_maximum: The maximum interval value.
        :type interval_maximum: int

        :param interval_minimum: The minimum interval value.
        :type interval_minimum: int

        :param wait_window: Time to wait for a window request.
        :type wait_window: float

        :param iterations: Number of iterations for the scheduling process.
        :type iterations: int

        :param random: Flag for random request processing.
        :type random: bool

        :param save_dids_list_pickle: Flag for saving DID lists as pickle files.
        :type save_dids_list_pickle: bool

        :param GUI_mode: Flag for GUI mode.
        :type GUI_mode: bool
        """

        self.GUI_mode = GUI_mode
        elapsed_time_list = []
        self.iteration_counter = 0
        self.random = random
        self.iterations = iterations
        self.wait_window_request = wait_window
        self.dids_in_request = dids_in_request

        if performance_list is not None:
            self.performance_dict = self.get_performance_dict(performance_list)

        self.set_up_dict_req_eval(
            self.number_of_requesters,
            self.interface,
            csv_filepath,
        )

        if (
            ignore_blacklisted_requests
        ):  # remove blacklisted requests from the request_list
            self.request_list.request_list = [
                request
                for request in self.request_list.request_list
                if not request.blacklisted
            ]

        while self.iteration_counter < self.iterations:
            self.iteration_counter += 1
            start_time = int(time.time())
            if not self.GUI_mode:
                question = f"\nAre you ready to start iteration {self.iteration_counter} of the population loop?"
                answer = misc.query_yes_no(question=question)
            else:
                answer = True

            if answer:
                if self.parallel:
                    self.start_threads()
                print(f"\nStarted Iteration {self.iteration_counter}")

                self.request_all()
                elapsed_time = int(time.time() - start_time)
                elapsed_time_list.append(elapsed_time)
                print(
                    f"\nFinished Iteration {self.iteration_counter} after {elapsed_time}s"
                )
                if self.parallel:
                    self.stop_threads()
            else:
                continue

        # Calculate the theoretical time it takes to loop through the list of not blacklisted requests
        # and the average request time.
        # This value is used in the calculation of the capacity.
        execution_durations = []
        for request in self.request_list.request_list:
            if not request.blacklisted:
                execution_durations.append(request.execution_duration)
        self.theoretical_loop_time = math.ceil(sum(execution_durations))
        self.average_request_time = self.theoretical_loop_time / len(
            execution_durations
        )
        print("Theoretical loop time: ", self.theoretical_loop_time, "s")
        print("Average request time: ", round(self.average_request_time, 3), "s")

    def get_signal_features(self):
        feature_sum_list = []
        for request in self.request_list.request_list:
            if isinstance(request, DoIPDidRequest):
                request.calculate_signal_feature()
                feature_sum_list.append(request.feature_sum)
        return feature_sum_list

    def filter_for_signal_features(self):
        feature_list = self.get_signal_features()
        # sortiere die Liste der Feature-Summen, höchste zuerst
        feature_list.sort(reverse=True)
        feature_sum_counts = [
            0
        ] * 20  # Liste für die Zählung der Feature-Summen initialisieren
        total_requests = len(
            self.request_list.request_list
        )  # Gesamtanzahl der Requests

        num_requests_zero_sum = 0  # Anzahl der Requests mit Feature-Summe 0

        # Zähle die Anzahl der Requests mit einer bestimmten Feature-Summe und die Anzahl der Requests mit Feature-Summe 0
        for feature in feature_list:

            if feature == 0:
                num_requests_zero_sum += 1
            else:
                bin_index = int(feature * 10)  # Index des Bereichs berechnen
                feature_sum_counts[
                    min(bin_index, 19)
                ] += 1  # Sicherstellen, dass der Index nicht größer als 19 wird

        # Ausgabe der Anzahl der Requests mit Feature-Summe 0
        print("Number of Requests with feature sum 0:", num_requests_zero_sum)

        # Ausgabe der Gesamtanzahl der Requests
        print("Number of Requests:", total_requests)

        # Ausgabe der Tabelle für die Feature-Summen
        print("Table for feature sum:")
        print("Area       | Number of Requests")
        print("----------------------------------")
        for i in range(20):  # 20 verschiedene Bereiche
            range_start = i / 10
            range_end = (i + 1) / 10
            count = feature_sum_counts[i]
            print(f"{range_start:0.1f} - {range_end:0.1f}   | {count:<18}")

        while True:
            print(
                "Please enter the number of DIDs, you want to request. The ones with the highest feature sum will be requested"
            )
            number_of_dids = int(input())
            print(
                f"All the Requests with a sum of {feature_list[number_of_dids-1]} will be requested"
            )
            question = "Are you sure you want to continue?"
            answer = misc.query_yes_no(question=question)
            if answer:
                self.filter_requests(feature_list[number_of_dids - 1])
                break
            else:
                continue

    def start_request_loop(
        self,
        iterations=10,
        performance_list=None,
        csv_filepath=None,
        dids_in_request=1,
        wait_window=1,
        ignore_blacklisted_requests=False,
    ):
        """
        Starts the parallel scheduling process with options for subsets and iterations.

        :param wait_window: Time to wait for a window request.
        :type wait_window: float

        :param iterations: Number of iterations for the scheduling process.
        :type iterations: int

        :param performance_list: The path to the performance list.
        :type performance_list: str

        :param csv_filepath: The path to the CSV file.
        :type csv_filepath: str

        :param dids_in_request: The number of DIDs in a request. Only applicable for parallel requests and if no performance list is provided.
        :type dids_in_request: int

        :param ignore_blacklisted_requests: Flag to ignore blacklisted requests.
        :type ignore_blacklisted_requests: bool

        """

        elapsed_time_list = []
        self.iteration_counter = 0
        self.random = random
        self.iterations = iterations
        self.wait_window_request = wait_window
        self.dids_in_request = dids_in_request

        if performance_list is not None:
            self.performance_dict = self.get_performance_dict(performance_list)

        self.set_up_dict_req_eval(
            self.number_of_requesters,
            self.interface,
            csv_filepath,
        )

        if (
            ignore_blacklisted_requests
        ):  # remove blacklisted requests from the request_list
            self.request_list.request_list = [
                request
                for request in self.request_list.request_list
                if not request.blacklisted
            ]

        question = f"\nAre you ready to start the Request?"
        answer = misc.query_yes_no(question=question)

        if answer:

            self.start_threads()
            server_id = self.request_list.request_list[0].ids.server_id
            tester_id = self.request_list.request_list[0].ids.tester_id
            self.start_capture_distribute_threads(server_id, tester_id)

            while self.iteration_counter < self.iterations:
                self.iteration_counter += 1
                start_time = int(time.time())
                print(
                    f"\n##############Iteration {self.iteration_counter}#################"
                )
                self.request_all()
                elapsed_time = int(time.time() - start_time)
                elapsed_time_list.append(elapsed_time)
                print(
                    f"\nFinished Iteration {self.iteration_counter} after {elapsed_time}s"
                )

            self.stop_threads()
            self.stop_capture_distribute_threads()
            print("finished")

    # funktioniert noch nicht richtig. ESC wird nicht wirklich vom Programm erkannt
    def request_until_esc(
        self,
        wait_window,
        GUI_mode=False,
        dids_in_request=1,
        parallel: bool = True,
        csv_filepath=None,
        performance_list=None,
        ignore_blacklisted_requests=False,
    ):
        """
        Requests until the ESC key is pressed.
        When the ESC key is pressed, all the request in this loop are requested and then the loop is exited.

        :param wait_window: Time to wait for a window request.
        :type wait_window: float

        :param GUI_mode: Flag for GUI mode.
        :type GUI_mode: bool

        :param dids_in_request: The number of DIDs in a request. Only applicable for parallel requests and if no performance list is provided.
        :type dids_in_request: int

        :param parallel: Flag for parallel request processing.
        :type parallel: bool

        :param csv_filepath: The path to the CSV file.
        :type csv_filepath: str

        :param performance_list: The path to the performance list.
        :type performance_list: str

        :param ignore_blacklisted_requests: Flag to ignore blacklisted requests.
        :type ignore_blacklisted_requests: bool

        :raises ValueError: If no requests are loaded.
        """

        self.GUI_mode = GUI_mode
        elapsed_time_list = []
        self.iteration_counter = 0
        self.wait_window_request = wait_window
        self.parallel = parallel
        self.dids_in_request = dids_in_request
        self.esc_pressed = False

        if performance_list is not None:
            self.performance_dict = self.get_performance_dict(performance_list)

        self.set_up_dict_req_eval(
            self.number_of_requesters,
            self.interface,
            csv_filepath,
        )

        if (
            ignore_blacklisted_requests
        ):  # remove blacklisted requests from the request_list
            self.request_list.request_list = [
                request
                for request in self.request_list.request_list
                if not request.blacklisted
            ]

        question = f"\nAre you ready to start the Request?"
        answer = misc.query_yes_no(question=question)

        if answer:
            print("Requesting until ESC is pressed")

            if self.parallel:
                self.start_threads()
                server_id = self.request_list.request_list[0].ids.server_id
                tester_id = self.request_list.request_list[0].ids.tester_id
                self.start_capture_distribute_threads(server_id, tester_id)

            while not self.esc_pressed:
                self.iteration_counter += 1
                print(
                    f"\n##############Iteration {self.iteration_counter}#################"
                )
                start_time = int(time.time())

                print(f"\nStarted Iteration {self.iteration_counter}")

                self.request_all()
                elapsed_time = int(time.time() - start_time)
                elapsed_time_list.append(elapsed_time)
                print(
                    f"\nFinished Iteration {self.iteration_counter} after {elapsed_time}s"
                )

            if self.parallel:
                self.stop_threads()
                self.stop_capture_distribute_threads()
                print("finished")

        else:
            return

    def filter_requests(self, min_feature_sum):
        """
        Filters requests based on the feature sum.

        :param min_feature_sum: The minimum feature sum.
        :type min_feature_sum: int
        """

        for request in self.request_list.request_list:
            if request.feature_sum < min_feature_sum:
                request.blacklisted = True

    def get_performance_dict(self, path):
        performance_dict = {}
        with open(path, "r") as file:
            # Die erste Zeile überspringen
            next(file)
            for line in file:
                line = line.split(",")
                server_id = int(line[0].strip('\''), 16)  # Hexadezimal in Dezimal umwandeln
                did_length = int(line[2].strip('\''))
                payload_length = int(line[2].strip().strip('\''))
                # Die Werte für jede Server-ID aktualisieren
                performance_dict[server_id] = {
                    "DID_length": did_length,
                    "Payload_length": payload_length,
                }

        return performance_dict

    def start(
        self,
        subsetnumber=0,
        iterations=10,
        duration=600,
        random: bool = False,
        ignore_blacklisted_requests=True,
        create_output_csv=False,
        print_info=False,
        output_directory=os.path.dirname(__file__),
        output_name=None,
        maximum_dids_in_request=1,
        GUI_mode=False,
    ):
        """
        Starts the scheduling process with options for subsets and iterations.

        :param subsetnumber: The number of the subset to process.
        :type subsetnumber: int

        :param iterations: Number of iterations for the scheduling process.
        :type iterations: int

        :param duration: The duration of the scheduling process.
        :type duration: int

        :param random: Flag for random request processing.
        :type random: bool

        :param ignore_blacklisted_requests: Flag to ignore blacklisted requests during scheduling.
        :type ignore_blacklisted_requests: bool

        :param create_output_csv: Flag indicating whether to create an output CSV file.
        :type create_output_csv: bool

        :param print_info: Flag for printing debugging information.
        :type print_info: bool

        :param output_directory: The directory for output files.
        :type output_directory: str

        :param output_name: The name for the output file.
        :type output_name: str

        :param GUI_mode: Flag for GUI mode.
        :type GUI_mode: bool
        """

        self.duration = duration
        subset_number = int(subsetnumber)
        self.random = random
        self.ignore_blacklisted_requests = ignore_blacklisted_requests
        self.create_output_csv = create_output_csv
        self.iterations = iterations
        self.print_info = print_info
        self.maximum_dids_in_request = maximum_dids_in_request
        subset = self.subset_lists[subset_number]

        if self.create_output_csv:
            if output_name == None:
                raise ValueError(
                    "csv_filename is required when create_output_csv is True."
                )
            self.csv_filepath = os.path.normpath(
                os.path.join(output_directory, output_name, ".csv")
            )
            self.set_up_dict_req_eval(
                self.number_of_requesters, self.interface, self.csv_filepath
            )
            self.create_evaluators(
                self.number_of_requesters,
                self.interface,
                self.csv_filepath,
                self.wait_window_request,
            )

        subset_threads = [
            threading.Thread(target=self.request)
            for thread in range(len(self.subset_lists))
        ]

        if self.GUI_mode:
            if output_name == None:
                raise ValueError(
                    "csv_filename is required when create_output_csv is True."
                )
            request_thread = threading.Thread(target=self.request)
            print(len(subset.request_list))
            if self.create_output_csv:
                file_string = output_name + "_subset_" + str(subset_number) + ".csv"
                self.csv_filepath = os.path.normpath(
                    os.path.join(output_directory, file_string)
                )
                if os.path.exists(self.csv_filepath):
                    # Open the file in write mode with truncation (clearing previous content)
                    with open(self.csv_filepath, "a", newline="") as csvfile:
                        csvfile.truncate(0)
                print(self.csv_filepath)

            self.end_time = time.time() + self.duration
            # print(f"Start request thread for subset {subset_number}")
            # self.request_thread.start()
            self.end_request_thread = False
            self.start_threads()  # creates threads for Requesters and Evaluators for later execution in send_request()
            request_thread.start()  # request_threads[subset_number].start()
            while time.time() < self.end_time:
                self.update(subset_number)
            print("\nFinished update.")
            self.end_request_thread = True
            request_thread.join()  # request_threads[subset_number].join()
            # self.request_thread.join()
            self.stop_threads()
            print("\nJoined thread.")
        else:
            for subset_number, subset in enumerate(self.subset_lists):
                question = f"\nSubset {(subset_number + 1)}/{len(self.subset_lists)} will be recorded now. Are you ready to continue?"
                answer = misc.query_yes_no(question=question)
                if answer:
                    if output_name == None:
                        raise ValueError(
                            "csv_filename is required when create_output_csv is True."
                        )
                    print(len(subset.request_list))
                    file_string = output_name + "_subset_" + str(subset_number) + ".csv"
                    self.csv_filepath = os.path.normpath(
                        os.path.join(output_directory, file_string)
                    )

                    if os.path.exists(self.csv_filepath):
                        # Open the file in write mode with truncation (clearing previous content)
                        with open(self.csv_filepath, "a", newline="") as csvfile:
                            csvfile.truncate(0)

                    print(self.csv_filepath)
                    self.end_time = time.time() + self.duration
                    # print(f"Start request thread for subset {subset_number}")
                    # self.request_thread.start()
                    self.end_request_thread = False
                    subset_threads[subset_number].start()
                    self.start_threads()  # creates threads for Requesters and Evaluators for later execution in send_request()
                    while time.time() < self.end_time:
                        self.update(subset_number)
                    print("\nFinished update.")
                    self.end_request_thread = True
                    subset_threads[subset_number].join()
                    # self.request_thread.join()
                    self.stop_threads()  # stops the threads for the Requesters and Evaluators
                    print("\nJoined thread.")
                else:
                    pass

    def update(self, subset_number):
        """
        Updates buffer_list during execution by comparing, when a request was executed last.

        :param subset_number: The number of the subset being updated.
        :type subset_number: int
        """

        if self.print_info:
            print("Start update iteration")
            random_number = random.randint(
                0, len(self.subset_lists[subset_number].request_list) - 1
            )
            print("Before adjusting for max requests")
            print(self.subset_lists[subset_number].request_list[random_number])

        self.subset_lists[subset_number].count_requests(self.print_info)

        # self.adjust_for_max_requests()

        if self.print_info:
            print("After adjusting for max requests")
            print(self.subset_lists[subset_number].request_list[random_number])

        self.add_requests_to_buffer(subset_number)

        while len(self.buffer_list) > 20:
            time.sleep(0.2)

    def add_requests_to_buffer(self, subset_number):
        """
        Adds requests to the buffer, if certain conditions are met.

        :param subset_number: The number of the subset being processed.
        :type subset_number: int
        """

        now = time.time()
        for request in self.subset_lists[subset_number].request_list:
            # Only add the request to the buffer list, if the following conditions are met:
            # 1. The time since the request has last been requested is larger than the current interval of the request
            # 2. The unique ID of the request is not already in the buffer list
            # 3. Either the attribute blacklisted of the request or the attribute ignore_blacklisted_requests of the Scheduler class
            #    are False; If ignore_blacklisted_requests is False, all requests will be scheduled, if ignore_blacklisted_requests
            #    is True, only not blacklisted requests will be scheduled
            if (
                (now - request.exec_time >= request.interval._current)
                and ((request.make_unique_ID()) not in self.added_to_buffer)
                and not (self.ignore_blacklisted_requests and request.blacklisted)
            ):
                self.buffer_list.append(request)
                self.added_to_buffer.add(request.make_unique_ID())

    def append_debug_history(self, request: DoIPDidRequest, new_interval):
        """
        Appends debug information of the request to the debug history.

        :param request: The request for which debug history is appended.
        :type request: DoIPDidRequest

        :param new_interval: The new interval value.
        :type new_interval: int
        """

        request.debug_history = request.debug_history + [
            [
                time.time(),
                new_interval,
                request.history.changing_bits_count,
                request.history.entropy,
                request.blacklisted,
            ]
        ]

    def adjust_for_max_requests(self):
        """
        Adjusts intervals to meet max requests requirement.
        """

        total_requests = self.calculate_send_count()
        max_requests = self.request_list.count_not_blacklisted
        iteration_counter = 0
        print(f"Total requests: {total_requests}; Max. requests: {max_requests}")

        while abs(total_requests - max_requests) > 0.05 * max_requests:
            for request in self.request_list.request_list:
                if not request.blacklisted:
                    # Multiplication solution
                    # new_interval = request.interval.current * (
                    #     total_requests / max_requests
                    # )
                    # Addition solution
                    if (total_requests / max_requests) > 1:
                        summand = 1
                    else:
                        summand = -0.1
                    new_interval = request.interval.current + summand
                    request.interval.update_current(new_interval)
                    self.append_debug_history(request, request.interval._current)
            total_requests = self.calculate_send_count()
            if self.print_info:
                print(
                    f"Total requests: {total_requests}; Max. requests: {max_requests}"
                )
            iteration_counter += 1
            if iteration_counter > 100:
                raise Exception(
                    "Could not adjust intervals enough in 100 iterations to meet requirement: Total requests ~ Max. requests"
                )

    def calculate_send_count(self):
        """
        Calculates the amount of requests that could be sent during the average loop time.

        :return: The total number of requests to be sent.
        :rtype: int
        """

        send_counts = []
        for request in self.request_list.request_list:
            if not request.blacklisted:
                send_counts.append(
                    self.theoretical_loop_time / request.interval.current
                )
        total_requests = math.ceil(sum(send_counts))
        return total_requests

    def send_request(self, request_list: list[DoIPDidRequest]):
        """
        Send a list of requests in parallel.
        """
        try:
            logging.debug("%s: Entering send_request()", time.time())
            unique_dids = self._get_unique_dids()
            self._handle_request_order(request_list, unique_dids)
            self._start_threads(request_list)
            logging.debug("%s: Leaving send_request()", time.time())
        except Exception as e:
            print("\nError in send_request():", e)

    def _get_unique_dids(self):
        """
        Get unique DIDs from current_request_dict.
        """
        unique_dids = [
            request["List"][0].ids.did
            for request in self.current_request_dict.values()
            if request.get("List")
        ]
        return unique_dids

    def _handle_request_order(self, request_list, unique_dids):
        """
        Ensure the first DID in request_list is unique.+
        Otherwise move the first DID to the first unique position.
        """
        dids = [request.ids.did for request in request_list]
        for i, did in enumerate(dids):
            if did not in unique_dids and i != 0:
                request_list[0], request_list[i] = request_list[i], request_list[0]
                break

    def _start_threads(self, request_list):
        """
        Add request_list to current_request_dict and start threads.
        """
        sent = False
        while not sent:
            for key, value in ParallelScheduler.current_request_dict.items():
                try:
                    if not self.doip_connector._initialized:
                        self.doip_connector.initiate_DoIP_client(
                            request_list[0].ids.tester_id
                        )
                    else:
                        if value["List"] is None or value["List"] == []:
                            ParallelScheduler.current_request_dict[key][
                                "List"
                            ] = request_list
                            ParallelScheduler.Evaluators[key].is_active = True
                            sent = True

                            logging.debug(
                                "\n%s Request assigned to Requester", time.time()
                            )

                            break
                except Exception as e:
                    for request in request_list:
                        self.request_list.request_list.append(request)
                        print(
                            "\n Request returned to request_list; Connection error:", e
                        )

    def start_threads(self):
        # Erstelle Threads für Requesters und Evaluatoren für spätere Ausführung in send_request()
        self.evaluate_threads = []
        self.request_threads = []
        for evaluator in ParallelScheduler.Evaluators:
            evaluator.evaluate_active = True

        for requester in ParallelScheduler.Requesters:
            requester.request_active = True

        self.evaluate_threads = [
            threading.Thread(target=evaluator.activate_evaluation)
            for evaluator in ParallelScheduler.Evaluators
        ]
        self.request_threads = [
            threading.Thread(target=requester.activate_request)
            for requester in ParallelScheduler.Requesters
        ]

        # Aktiviere die Threads für die Evaluatoren
        for thread in self.evaluate_threads:
            thread.start()

        # Aktiviere die Threads für die Requester
        for thread in self.request_threads:
            thread.start()

    def stop_threads(self):
        for requester in ParallelScheduler.Requesters:
            requester.stop_request()
        for evaluator in ParallelScheduler.Evaluators:
            evaluator.stop_evaluation()

        for thread in self.evaluate_threads:
            thread.join()
        for thread in self.request_threads:
            thread.join()
        return

    def request(self):
        """
        Main method for executing requests in a separate thread.
        """
        while True:
            if self.end_request_thread:
                print("Entered if end request")
                break
            if len(self.buffer_list) > 0:

                # get all (maximum is self.maximum_dids_in_request) request with the same server_id in buffer_list
                request_list: list[DoIPDidRequest] = []
                request_list.append(self.buffer_list.pop(0))
                i = 0
                while i < len(self.buffer_list):
                    if (
                        self.buffer_list[i].ids.server_id
                        == request_list[0].ids.server_id
                    ):
                        request_list.append(self.buffer_list[i])
                        self.buffer_list.pop(i)  # Remove the item from buffer_list
                        if len(request_list) == self.maximum_dids_in_request:
                            i = len(self.buffer_list)  # ends the while loop
                    else:
                        i += 1

                self.send_request(
                    request_list
                )  # makes the request and handles the Threads

                """ ###not used###
                self.added_to_buffer.discard(request.make_unique_ID())
                if self.random:
                    response, execution_time, unique_ID = request.get_rnd_value()
                    request.update_interval(self.iterations)
                else:
                    response, execution_time, unique_ID = request.get_value(
                        self.wait_window_request
                    )
                    request.update_interval(self.iterations)
                if self.create_output_csv and response:
                    # ------------------------------------------------------
                    # Reason for the next if-Statement: During testing the csv-Saving crashed while using the GUI. at somepoint during Recording "Errno 13 Permission denied" appeared and the program crashed. Bug couldn't be found so the csv is saved after each subset
                    # TODO: save files in anians manual mode in the same way if he's ok with that
                    # Anian is OK with that ;)
                    # ------------------------------------------------------
                    if self.GUI_mode:
                        self.subset_payload_for_csv.append(
                            [execution_time, unique_ID] + response
                        )
                    else:
                        self.append_to_output_csv(response, execution_time, unique_ID)
                """

                print(
                    f"\rCurrent time: {time.strftime('%T', time.localtime(time.time()))}, Target time: {time.strftime('%T', time.localtime(self.end_time))}, buffer length: {len(self.buffer_list)}  ",
                    end="",
                )
        if self.GUI_mode:
            for row in self.subset_payload_for_csv:
                self.append_to_output_csv(row[2:], row[0], row[1])
            self.subset_payload_for_csv = []
        print("Thread finished.")

    def append_to_output_csv(self, response, execution_time, unique_ID):
        """
        Appends results to the output CSV file.

        :param response: The response data to be appended.
        :type response: list

        :param execution_time: The execution time of the request.
        :type execution_time: float

        :param unique_ID: The unique ID of the request.
        :type unique_ID: int
        """

        if self.csv_filepath is not None:
            with open(self.csv_filepath, "a") as file:
                writer = csv.writer(file)
                writer.writerow([execution_time, unique_ID, response])
        else:
            print("No csv file path specified.")

    @classmethod
    def set_up_capture_dict(cls, number_of_evaluators: int):
        """
        Sets up the capture dictionary.

        :param number_of_evaluators: The number of evaluators.
        :type number_of_evaluators: int
        """
        cls.capture_dict = defaultdict(list)
        for i in range(number_of_evaluators):
            cls.capture_dict[i] = []

    @classmethod
    def create_current_request_dict(cls, number_of_requesters: int):
        """
        Creates a dictionary of requests.

        :param number_of_requesters: The number of requesters.
        :type number_of_requesters: int
        """
        cls.current_request_dict = {}
        for i in range(number_of_requesters):
            cls.current_request_dict[i] = {
                "Sent": False,
                "List": None,
            }

    @classmethod
    def create_requesters(cls, number_of_requesters: int):
        """
        Creates a list of Requester instances.

        :param number_of_requesters: The number of requesters.
        :type number_of_requesters: int
        """
        cls.Evaluators = []
        cls.Requesters = [Requester(i) for i in range(number_of_requesters)]

    @classmethod
    def create_evaluators(cls, number_of_evaluators, interface, csv_filepath, timeout):
        """
        Creates a list of Evaluator instances.

        :param number_of_evaluators: The number of evaluators.
        :type number_of_evaluators: int
        """
        cls.Evaluators = []
        cls.Evaluators = [
            Evaluator(i, interface, csv_filepath) for i in range(number_of_evaluators)
        ]

    def capture_task(self, server_id, tester_id, timeout_value=1):
        """
        Captures the response data.
        Runs in a separate thread.
        """
        client = self.doip_connector.get_client(server_id, tester_id)
        if client.conn.is_open():
            self.capture_active = True
        else:
            client.open()
            self.capture_active = True

        while self.capture_is_active:
            if client.conn.is_open():
                payload = client.conn.wait_frame_complete_message(
                    timeout=timeout_value
                )  # wait for a response
                if payload:
                    self.capture_list.append(payload)
                    logging.debug(
                        "\n%s: Received answer: %s",
                        time.time(),
                        bytes(payload.user_data),
                    )
            else:
                client.open()  # Reopen the connection if it was closed

    def distribute_responses(self):
        """
        Distributes the responses to the respective evaluators.
        Runs in a separate thread.
        """
        while self.distribute_active:
            try:
                if self.capture_list:
                    logging.debug("\n%s: Distributing responses", time.time())
                    for payload in self.capture_list:
                        response = Response.from_payload(bytes(payload.user_data))
                        if response and response.positive and response.data is not None:
                            identifier = (response.data[0] << 8) | response.data[1]
                            server = payload.source_address
                            for i in range(self.number_of_requesters):
                                if (
                                    self.current_request_dict[i]["List"]
                                    and self.current_request_dict[i]["Sent"] is True
                                ):
                                    if (
                                        server
                                        == self.current_request_dict[i]["List"][
                                            0
                                        ].ids.server_id
                                    ):
                                        try:
                                            did_list = [
                                                request.ids.did
                                                for request in self.current_request_dict[
                                                    i
                                                ][
                                                    "List"
                                                ]
                                            ]
                                        except:
                                            logging.debug(
                                                "\n%s: DID-List not creatable",
                                                time.time(),
                                            )

                                        if identifier in did_list:
                                            self.capture_dict[i].append(response.data)

                                            logging.debug(
                                                "\n%s: added to capture_dict: %s",
                                                time.time(),
                                                response.data,
                                            )
                                            self.capture_list.remove(payload)
                                            break
                                    else:
                                        logging.debug(
                                            "\n%s: Server not matching", time.time()
                                        )
                            else:
                                logging.debug("\n%s: Request not found", time.time())
                                self.capture_list.remove(payload)

                        elif response and (
                            response.code == ResponseCode.RequestOutOfRange
                            or response.code == ResponseCode.ResponseTooLong
                        ):
                            # remove the request from the current_request_dict
                            for i in range(self.number_of_requesters):
                                if (
                                    self.current_request_dict[i]["List"]
                                    and self.current_request_dict[i]["Sent"] is True
                                ):
                                    if (
                                        server
                                        == self.current_request_dict[i]["List"][
                                            0
                                        ].ids.server_id
                                    ):
                                        self.current_request_dict[i]["List"] = None
                                        self.current_request_dict[i]["Sent"] = False
                                        self.capture_list.remove(payload)
                        elif (
                            response
                            and response.code
                            == ResponseCode.RequestCorrectlyReceived_ResponsePending
                        ):
                            self.capture_list.remove(payload)
                            ##TODO: handle request out of range
                            # schedule the request again but in single mode
                            # shouldn't be necessary, because of the dids perfomance algorith

            except Exception as e:
                print("Error in distribute_responses():", e)

    def return_to_request_list(self, request_list, requester_number):
        for request in request_list:
            self.request_list.request_list.append(request)

        self.Evaluators[requester_number].clear_all_after_evaluation()
        print("Requests returned to request_list")


class Requester:
    """
    A class for managing requests and sending them to the vehicle.

    Attributes:
    - requester_number: The number of the requester.
    - request_list: A list of requests to be sent.
    - is_active: Flag indicating whether the requester is active.

    Methods:
    - __init__: Initializes the Requester instance.
    - request: Sends requests to the vehicle.
    - create_didlist: Creates a list of DIDs to be requested.
    - add_request_to_request_dict: Adds a request to the request list.
    """

    def __init__(self, requester_number: int):
        self.requester_number = requester_number
        self.request_list: list[DoIPDidRequest] = []
        self.request: Request
        self.request_active = True

    def stop_request(self):
        self.request_active = False

    def activate_request(self):
        while self.request_active:
            if not ParallelScheduler.current_request_dict[self.requester_number][
                "Sent"
            ]:
                request_list = ParallelScheduler.current_request_dict[
                    self.requester_number
                ]["List"]
                if request_list:
                    self.make_request()
                    time.sleep(0.0001)
        else:
            return

    def make_request(self):
        try:
            self.request_list = ParallelScheduler.current_request_dict[
                self.requester_number
            ]["List"]
            if self.request_list:
                client = DoIPConnector.get_client(
                    self.request_list[0].ids.server_id,
                    self.request_list[0].ids.tester_id,
                )
                did_list = self.create_didlist()
                request = services.ReadDataByIdentifier.make_request(didlist=did_list)
                ParallelScheduler.current_request_dict[self.requester_number][
                    "Sent"
                ] = True
                try:
                    client.send_request_no_response(request)
                except:
                    ParallelScheduler.current_request_dict[self.requester_number][
                        "Sent"
                    ] = False
            else:
                logging.debug("%s\nNo requests to send", time.time())

        except Exception as e:
            self.request_list = ParallelScheduler.current_request_dict[
                self.requester_number
            ]["List"]
            # ParallelScheduler.return_to_request_list(
            #     request_list=self.request_list, requester_number=self.reqester_number
            # )
            print("Error in Requester: make_request():", e)

    def create_didlist(self):
        try:
            did_list = [request.ids.did for request in self.request_list]
            return did_list
        except:
            print("Error in create_didlist, did_list not returnable")


class Evaluator:
    def __init__(
        self, evaluator_number: int, interface: str, csv_filepath: str, timeout: int = 3
    ):
        self.interface = interface
        self.evaluator_number = evaluator_number
        self.csv_filepath = csv_filepath
        self.request_list: list[DoIPDidRequest]
        self.timeout = timeout
        self.is_active = False
        self.csv_data = []  # Buffer for batch writing
        self.evaluate_active = True

    def stop_evaluation(self):
        self.write_to_csv()
        self.evaluate_active = False

    def activate_evaluation(self):
        while self.evaluate_active:
            if (
                self.is_active
                and ParallelScheduler.current_request_dict[self.evaluator_number][
                    "Sent"
                ]
            ):
                self.start_evaluation()
            time.sleep(0.0001)
        else:
            return

    def start_evaluation(self):
        self.search_for_payload()

    def search_for_payload(self):
        try:
            if (
                ParallelScheduler.current_request_dict[self.evaluator_number]["List"]
                is not None
                and not []
            ):
                self.request_list = ParallelScheduler.current_request_dict[
                    self.evaluator_number
                ]["List"]

                did_list = [
                    request.ids.did
                    for request in ParallelScheduler.current_request_dict[
                        self.evaluator_number
                    ]["List"]
                ]
                start_time = time.time()
                while time.time() - start_time < self.timeout:
                    try:
                        if ParallelScheduler.capture_dict[self.evaluator_number]:
                            for resp in ParallelScheduler.capture_dict[
                                self.evaluator_number
                            ]:
                                response = list(resp)
                                did = (response[0] << 8) | response[1]

                                if (
                                    did in did_list
                                ):  # already checked in distribution, but to make sure
                                    self.evaluate_payload(response)
                                    return
                    except Exception as e:
                        print("Error in search_for_payload() inner Loop:", e)
                self.handle_timeout()

        except Exception as e:
            print("Error in search_for_payload():", e)
            self.handle_timeout()

    def evaluate_payload(self, payload):
        logging.debug("\n%s start Evaluation", time.time())
        try:
            payload_copy = payload.copy()
            while payload:
                did = (payload[0] << 8) | payload[1]  # get the DID from the payload
                payload = payload[2:]  # removes identifier
                for request in self.request_list:  #
                    if request.ids.did == did:
                        data = payload[: request.ids.payload_length]
                        payload = payload[
                            request.ids.payload_length :
                        ]  # remove the data from the payload
                        request.enter_values(data)
                        if self.csv_filepath:
                            self.csv_data.append(
                                (
                                    time.time(),
                                    request.unique_ID,
                                    data,
                                    0,
                                    self.evaluator_number,
                                )
                            )  # Append data as it is
                        self.request_list.remove(request)
                        break
                else:  # if no request was found for a did set timeout for the remaining requests
                    self.handle_timeout()
                    self.clear_all_after_evaluation()
                    return

            # handle timeout for requests that did not return a response
            for request_2 in self.request_list:
                logging.info(
                    f"{time.time()} no Response for {request_2.make_unique_ID()}"
                )

                if self.csv_filepath:
                    self.csv_data.append(
                        (time.time(), request_2.unique_ID, [], self.evaluator_number, 1)
                    )
        except Exception as e:
            print("Error in evaluate_payload():", e)
            self.handle_timeout()

        logging.debug("\n%s end Evaluation", time.time())
        self.clear_all_after_evaluation()

    def handle_timeout(self):
        logging.debug("\n%s Timeout Handling started", time.time())
        try:
            if self.csv_filepath:
                for did in self.request_list:
                    self.csv_data.append(
                        (
                            time.time(),
                            did.make_unique_ID(),
                            [],
                            1,
                            self.evaluator_number,
                        )
                    )
                    logging.info(f"{time.time()} Timeout for {did.make_unique_ID()}")

        except:
            pass
        self.clear_all_after_evaluation()

    def clear_all_after_evaluation(self):
        logging.debug("%s: start Clearing all after evaluation", time.time())
        if self.csv_data and len(self.csv_data) > 50:
            self.write_to_csv()
        ParallelScheduler.current_request_dict[self.evaluator_number]["Sent"] = False
        ParallelScheduler.current_request_dict[self.evaluator_number]["List"] = None
        self.request_list = []
        self.is_active = False
        ParallelScheduler.capture_dict[self.evaluator_number] = []
        logging.debug("%s: Cleared all after evaluation", time.time())

    def write_to_csv(self):
        with open(self.csv_filepath, "a") as file:
            # add header if file is empty
            if os.stat(self.csv_filepath).st_size == 0:
                writer = csv.writer(file)
                writer.writerow(
                    [
                        "Timestamp",
                        "Unique ID",
                        "Response",
                        "Timeout",
                        "Evaluator Number",
                    ]
                )
            writer = csv.writer(file)
            writer.writerows(self.csv_data)
            file.flush()  # Flush to ensure data is written immediately
            self.csv_data = []  # Clear buffer
