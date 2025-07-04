from pydantic import BaseModel, validator, field_validator
from revcan.reverse_engineering.models.car_metadata import Car, Server, Parameter
import datetime
import pandas as pd
from typing import List, Union
import logging
from bisect import bisect_left

class Value(BaseModel):
    time:datetime.datetime
    value: List[int]

    @field_validator('value', mode='before')
    def convert_bytes_to_list(cls, value):
        if isinstance(value, bytes):
            return list(value)  # Convert bytes to a list of integers.
        elif not isinstance(value, list):
            print(f"\nWarning: Input should be a valid list or bytes, but type is {type(value)}.")
            return []
        else:
            # Simply return the value
            return value


class Signal(BaseModel):
    serverid: int
    did: Parameter
    values: List[Value]

class Extern_Signal(BaseModel):
    name: str
    id: int
    values: List['Value'] # Union[List['Value'], List[str]]

class Extern_Alphanumeric_Signal(BaseModel):
    name: str
    id: int
    values: List[str]

class Experiment(BaseModel):
    starttime: datetime.datetime
    name: str
    description: str
    experiment_runtime_seconds: float = 0.0
    car: Car
    measurements: List[Signal]
    external_measurements : List[Extern_Signal]
    external_alphanumeric_measurements: List[Extern_Alphanumeric_Signal]=[]

    @classmethod
    def create_empty_experiment(cls):  
        return Experiment(
            starttime=datetime.datetime.now(),
            name="",
            description="",
            experiment_runtime_seconds = 0,
            car=Car.create_empty_Car(),
            measurements=[],
            external_measurements=[]
        )

    @classmethod
    def load(cls, filePath: str):
        with open(filePath, "r", encoding="utf-8") as f:
            return Experiment.model_validate_json(f.read())
    

    def get_signal_by_ids (experiment, server_id:int, did:int) -> Signal|None:
        for signal in experiment.measurements:
            if signal.serverid == server_id and signal.did.did == did:
                return signal
            
    @classmethod
    def get_current_groundtruth_value(cls, groundtruthsignal: Extern_Signal, timestamp: datetime.datetime ) -> List[int] :
        #assumes that the values are ordered
        timestamps = [value.time for value in groundtruthsignal.values]

        pos = bisect_left(timestamps, timestamp)

        # Determine the closest timestamp
        if pos == 0:
            closest_value = groundtruthsignal.values[0].value  # Closest is the first item
        elif pos == len(timestamps):
            closest_value = groundtruthsignal.values[-1].value  # Closest is the last item
        else:
            # Check the nearest of the two candidates
            before = groundtruthsignal.values[pos - 1]
            after = groundtruthsignal.values[pos]
            closest_value = before.value if abs(before.time - timestamp) <= abs(after.time - timestamp) else after.value
            
        return closest_value


    def filter_signals_by_bitflip_rate(experiment,
                          keep_values_flag: bool,
                          minimum_number_of_values=2,
                          minimum_biflip_rate=0.0,
                          maximum_bitflip_rate=1.0,
                          print_results=True,
                          activate_logging_flag=False,
                          ):
        #inner function to calculate bitflip rate
        def calculate_bitflip_rate(value1: List[int],
                           value2: List[int],
                           ):
            # TODO: Check method for LSBF and MSBF
            total_bit_flips = 0
            total_bit_comparisons = 0

            min_length = min(len(value1), len(value2))

            for i in range(min_length):
                # Compute the bitwise XOR of two integers to find differing bits.
                xor_result = value1[i] ^ value2[i]
                # Count the number of differing bits (Hamming distance).
                bit_flips = bin(xor_result).count('1')
                total_bit_flips += bit_flips
                # Total bit comparisons = number of bits in the binary representation
                # of the largest number encountered.
                total_bit_comparisons += value1[i].bit_length()

            # Add bitflips if values differ in length
            if len(value1) > len(value2):
                for i in range(len(value2), len(value1)):
                    total_bit_comparisons += value1[i].bit_length()
                    total_bit_flips += value1[i].bit_length()
            elif len(value1) < len(value2):
                for i in range(len(value1), len(value2)):
                    total_bit_comparisons += value2[i].bit_length()
                    total_bit_flips += value2[i].bit_length()

            # Calculate the flip rate as the total bit flips divided by total bit comparisons.
            flip_rate = total_bit_flips / total_bit_comparisons if total_bit_comparisons > 0 else 0.0

            return flip_rate

        if minimum_number_of_values < 2:
            print(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')
            if activate_logging_flag:
                logging.warning(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')    

        signals_to_keep = []

        for signal in experiment.measurements:
            # Check if at least minimum_number_of_values are present
            if len(signal.values) < minimum_number_of_values:
                print(f'Error: Less than {minimum_number_of_values} values for did {signal.did} on server {signal.serverid}.')
                if activate_logging_flag:
                    logging.warning(f'Error: Less than two values for did {signal.did} on server {signal.serverid}.')
                #signals_to_be_removed.append(signal)
            else:
                # Calculate average bitflip rate for the singal's values
                number_of_values = len(signal.values)
                bitflip_rate = 0.0
                for i in range(number_of_values-1):
                    bitflip_rate += calculate_bitflip_rate(signal.values[i].value, signal.values[i+1].value)
                bitflip_rate = bitflip_rate / number_of_values
                if bitflip_rate < minimum_biflip_rate or bitflip_rate > maximum_bitflip_rate:
                    #signals_to_be_removed.append(signal)
                    pass
                else:
                    signals_to_keep.append(signal)     
                
        experiment.measurements = signals_to_keep

        return experiment


    def keep_constant_signals(experiment,
                          keep_values_flag: bool,
                          minimum_number_of_values=2,

                          activate_logging_flag=False,
                          ):
        if minimum_number_of_values < 2:
            print(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')
            if activate_logging_flag:
                logging.warning(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')  

        #signals_to_be_removed = []
        signals_to_keep = []

        for signal in experiment.measurements:
            # Check if at least minimum_number_of_values are present
            if len(signal.values) < minimum_number_of_values:
                print(f'Error: Less than {minimum_number_of_values} values for did {signal.did} on server {signal.serverid}.')
                if activate_logging_flag:
                    logging.warning(f'Error: Less than two values for did {signal.did} on server {signal.serverid}.')
                #signals_to_be_removed.append(signal)
            else:
                if all(val.value == signal.values[0].value for val in signal.values):
                    # Signal is constant
                    if not keep_values_flag:
                        signal.values = []
                    signals_to_keep.append(signal)    
                else:
                    # Signal is non-constant
                    #signals_to_be_removed.append(signal)
                    pass
                
        experiment.measurements = signals_to_keep

        return experiment    
    
    def keep_non_constant_signals(experiment,
                            keep_values_flag= True,
                            minimum_number_of_values=2,
                            activate_logging_flag=False,
                              ):
        if minimum_number_of_values < 2:
            print(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')
            if activate_logging_flag:
                logging.warning(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')  

        signals_to_keep = []

        for signal in experiment.measurements:
            # Check if at least minimum_number_of_values are present
            if len(signal.values) < minimum_number_of_values:
                print(f'Error: Less than {minimum_number_of_values} values for did {signal.did} on server {signal.serverid}.')
                if activate_logging_flag:
                    logging.warning(f'Error: Less than two values for did {signal.did} on server {signal.serverid}.')
                #signals_to_be_removed.append(signal)
            else:
                if not all(val.value == signal.values[0].value for val in signal.values):
                    # Signal is non-constant
                    if not keep_values_flag:
                        signal.values = []
                    signals_to_keep.append(signal)    
                else:
                    # Signal is constant
                    #signals_to_be_removed.append(signal)
                    pass
                
        experiment.measurements = signals_to_keep

        return experiment

    def keep_non_repeating_signals(experiment,
                            keep_values_flag: bool,
                            minimum_number_of_values=2,
                            activate_logging_flag=False,
                              ):
        if minimum_number_of_values < 2:
            print(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')
            if activate_logging_flag:
                logging.warning(f'Error: minimum_number_of_values < 2: minimum_number_of_values = {minimum_number_of_values}.')  

        signals_to_keep = []

        for signal in experiment.measurements:
            # Check if at least minimum_number_of_values are present
            if len(signal.values) < minimum_number_of_values:
                print(f'Error: Less than {minimum_number_of_values} values for did {signal.did} on server {signal.serverid}.')
                if activate_logging_flag:
                    logging.warning(f'Error: Less than two values for did {signal.did} on server {signal.serverid}.')
                #signals_to_be_removed.append(signal)
            else:   
                values_list = [tuple(val.value) if isinstance(val.value, list) else val.value for val in signal.values]  
                if len(signal.values) == len(set(values_list)):
                    # Signal has no repeating values
                    if not keep_values_flag:
                        signal.values = []
                    signals_to_keep.append(signal)    
                else:
                    # Signal has repeating values
                    #signals_to_be_removed.append(signal)
                    pass
                
        experiment.measurements = signals_to_keep

        return experiment

    def keep_signals_by_list(experiment,
                             signals_list: List[Signal],
                             keep_values_flag: bool=True,
                             activate_logging_flag=False,
                          ):

        signals_to_keep = []

        for signal in experiment.measurements:
            if any(s.serverid == signal.serverid and s.did == signal.did for s in signals_list):
                # Signal is in list
                if not keep_values_flag:
                    signal.values = []
                signals_to_keep.append(signal)    
                
        experiment.measurements = signals_to_keep

        return experiment    
    
    def save(self, filePath: str):
        with open(filePath, "w", encoding="utf-8") as f:
            json = self.model_dump_json(serialize_as_any=True)
            f.write(json)

    def create_pandas_series(self, signal: Signal) :
        values = pd.concat([pd.Series(signal.values[i].value for i in range(0, len(signal.values)))])
        times = pd.concat([pd.Series(signal.values[i].time for i in range(0, len(signal.values)))])
        time_series = pd.Series(data=values.values, index=pd.to_datetime(times.values))
        return time_series
    
    def signals_w_incorrect_num_of_values(self, num_samples: int):
        signals = []
        for signal in self.measurements:
                if (len(signal.values) == num_samples):
                    continue
                else:
                    signals.append(signal)
        return signals



