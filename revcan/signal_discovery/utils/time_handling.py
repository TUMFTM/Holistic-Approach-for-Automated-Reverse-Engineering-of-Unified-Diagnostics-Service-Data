from datetime import datetime, timedelta


class TimeHandler:
    available_list = []
    not_available_list = []

    def __init__(self, address):
        self.address = address

    class UnavailableDID:
        def __init__(self, did, time):
            self.did = did
            self.time = time
            self.append_to_list()

        def append_to_list(self):
            TimeHandler.not_available_list.append(self)

    class AvailableDID:
        def __init__(self, did, time, payload):
            self.did = did
            self.time = time
            self.payload = payload
            self.append_to_list()

        def append_to_list(self):
            TimeHandler.available_list.append(self)

    @classmethod
    def calculate_average_available(cls):
        # Calculate the average datetime
        average_datetime = sum(cls.available_list.time, timedelta()) / len(
            cls.available_list
        )
        return average_datetime

    @classmethod
    def calculate_average_not_available(cls):
        # Calculate the average datetime
        average_datetime = sum(cls.not_available_list.time, timedelta()) / len(
            cls.not_available_list
        )
        return average_datetime

    @classmethod
    def total_time(cls):
        starttime = min(cls.available_list.time[0], cls.not_available_list.time[0])
        stoptime = max(cls.available_list.time[-1], cls.not_available_list.time[-1])

        return stoptime - starttime
