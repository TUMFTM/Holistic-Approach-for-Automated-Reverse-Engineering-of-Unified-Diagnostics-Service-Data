"""
This module defines the class Scheduler for managing and scheduling requests.
It handles loading and saving requests, executing requests in subsets, and maintaining scheduling-related attributes.
"""

from revcan.signal_discovery.doip_dids import (
    RequestID,
    DoIPDidRequest,
    RequestList,
    DidRequestDatabase,
    DoIPConnector,
)

from utils.network_actions import NetworkActions
import revcan.signal_discovery.utils.misc_methods as misc
import threading
import time
import math
import random
import os
import csv
import pickle


class Scheduler:
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

    def __init__(self, interface: str):
        """
        Initializes the Scheduler instance.
        """

        self.request_list: RequestList = RequestList()
        self.subset_lists: list[RequestList] = []
        self.buffer_list: list[DoIPDidRequest] = []
        self.connection = NetworkActions(
            interface
        )  # initiates a connection to the vehicle using the ethernet interface of the computer
        if interface != "test":
            self.doip_connector: DoIPConnector = DoIPConnector()
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
        self.request_thread = threading.Thread(target=self.request)
        self.request_thread.daemon = True
        self.end_request_thread = False
        self.update_thread = threading.Thread(target=self.update)
        self.update_thread.daemon = True

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

    def load_requests(self, path, maximum_payload_length=-1):
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
                load_path, want_payload_history=True
            )
        else:
            print("Directory")
            self.request_list.fill_request_list_from_database_files(
                load_path, want_payload_history=True
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
            # database.reset_database()
            database.store_list(self.request_list.request_list)
            if export_csv:
                database.export_db_as_csv()

    def request_all(self):
        """
        Executes requests for the entire request list once.
        """

        elapsed_time = []
        for i, request in enumerate(self.request_list.request_list):
            start = time.time()
            if self.random:
                request.get_rnd_value()
            else:
                request.get_value(self.wait_window_request)
            elapsed = time.time() - start
            elapsed_time.append(elapsed)
            self.average = round(sum(elapsed_time) / len(elapsed_time), 3)
            left = len(self.request_list.request_list) - i
            target_time = time.time() + (self.average * left)
            self.remaining_time = int(target_time - time.time())
            target_time = time.strftime("%T", time.localtime(target_time))
            current_time = time.strftime("%T", time.localtime(time.time()))
            print(
                f"\rCurrent time: {current_time}, Target time: {target_time}, Remaining: {self.remaining_time}s, Left: {left}, Average request time: {round(self.average,3)}",
                end="",
            )

    def populate_history(
        self,
        interval_maximum,
        interval_minimum,
        wait_window,
        iterations=10,
        random=True,
        save_dids_list_pickle=False,
        GUI_mode=False,
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
        while self.iteration_counter < self.iterations:
            self.iteration_counter += 1
            start_time = int(time.time())
            if not self.GUI_mode:
                question = f"\nAre you ready to start iteration {self.iteration_counter} of the population loop?"
                answer = misc.query_yes_no(question=question)
            else:
                answer = True

            if answer:
                print(f"\nStarted Iteration {self.iteration_counter}")
                self.request_all()
                elapsed_time = int(time.time() - start_time)
                elapsed_time_list.append(elapsed_time)
                print(
                    f"\nFinished Iteration {self.iteration_counter} after {elapsed_time}s"
                )
            else:
                return 1

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
        # Set interval values for each request
        for request in self.request_list.request_list:
            request.interval.maximum = interval_maximum
            request.interval.minimum = interval_minimum
            request.interval._current = request.interval.maximum
            request.update_interval(self.iterations)
            self.append_debug_history(request, request.interval._current)

        if not self.GUI_mode:
            if self.check_if_subsets_necessary():
                question = "There are too many requests to be all requested in one go. Do you want to split them up? (recommended)"
                answer = misc.query_yes_no(question=question)
                if answer:
                    self.split_request_list()
                else:
                    self.subset_lists = [self.request_list]
            else:
                self.subset_lists = [self.request_list]

        else:
            if save_dids_list_pickle == True:
                self.feature_sum_dict = {}
                for request in self.request_list.request_list:
                    self.feature_sum_dict.update(
                        {str(request.ids): {"feature-sum": request.feature_sum}}
                    )

                with open("feature_sum_dict.pkl", "wb") as f:
                    pickle.dump(self.feature_sum_dict, f)

    def check_if_subsets_necessary(self):
        """
        Checks if subsets are necessary based on request count.

        :return: True if subsets are necessary, False otherwise.
        :rtype: bool
        """

        total_requests = self.calculate_send_count()
        self.request_list.count_requests()
        max_requests = self.request_list.count_not_blacklisted
        number_subsets = round(total_requests / max_requests)
        if number_subsets == 0:
            number_subsets = 1
        print("Number of subsets: ", number_subsets)
        if number_subsets > 1:
            return True
        else:
            return False

    def split_request_list(self) -> list[RequestList]:
        """
        Splits the request list into subsets if necessary.
        """

        # Sort the requests based on their intervals in ascending order
        sorted_requests = sorted(
            self.request_list, key=lambda req: req.interval._current
        )

        total_requests = self.calculate_send_count()
        self.request_list.count_requests()
        max_requests = self.request_list.count_not_blacklisted
        number_subsets = int(
            total_requests / max_requests
        )  # round(total_requests / max_requests)
        if number_subsets == 0:
            number_subsets = 1
        print(f"Total requests: {total_requests}; Max. requests: {max_requests}")
        print("Number of subsets: ", number_subsets)

        # Initialize an empty list of subsets
        subsets = [[] for _ in range(number_subsets)]

        # Distribute the requests across subsets in a round-robin fashion
        for i, req in enumerate(sorted_requests):
            subset_index = i % number_subsets
            subsets[subset_index].append(req)

        subsets_out = []

        for subset in subsets:
            new_request_list = RequestList()
            new_request_list.request_list = subset
            subsets_out.append(new_request_list)

        self.subset_lists = subsets_out

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
        if self.create_output_csv:
            if output_name == None:
                raise ValueError(
                    "csv_filename is required when create_output_csv is True."
                )
        # request_threads = [
        #     threading.Thread(target=self.request)
        #     for thread in range(len(self.subset_lists))
        # ]
        if self.GUI_mode:
            subset = self.subset_lists[subset_number]
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
            request_thread.start()  # request_threads[subset_number].start()
            while time.time() < self.end_time:
                self.update(subset_number)
            print("\nFinished update.")
            self.end_request_thread = True
            request_thread.join()  # request_threads[subset_number].join()
            # self.request_thread.join()
            print("\nJoined thread.")
        else:
            request_threads = [
                threading.Thread(target=self.request)
                for thread in range(len(self.subset_lists))
            ]
            for subset_number, subset in enumerate(self.subset_lists):
                question = f"\nSubset {(subset_number + 1)}/{len(self.subset_lists)} will be recorded now. Are you ready to continue?"
                answer = misc.query_yes_no(question=question)
                if answer:
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
                    request_threads[subset_number].start()
                    while time.time() < self.end_time:
                        self.update(subset_number)  # läuft immer wieder durch
                    print("\nFinished update.")
                    self.end_request_thread = True
                    request_threads[subset_number].join()
                    # self.request_thread.join()
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
            time.sleep(0.5)

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
                request.history.power_spectrum_density,
                request.history.frequency_ratio,
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

    def request(self):
        """
        Main method for executing requests in a separate thread.
        """

        while True:
            if self.end_request_thread:
                print("Entered if end request")
                break
            if len(self.buffer_list) > 0:
                request = self.buffer_list.pop(0)
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

        with open(self.csv_filepath, "a") as file:
            writer = csv.writer(file)
            writer.writerow([execution_time, unique_ID, response])
