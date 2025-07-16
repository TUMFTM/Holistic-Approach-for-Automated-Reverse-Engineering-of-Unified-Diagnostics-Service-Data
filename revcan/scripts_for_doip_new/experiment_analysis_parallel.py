import multiprocessing
from typing import List
import numpy as np
from pathlib import Path
import os
import subprocess
import argparse
from datetime import datetime
from numpy import  ndarray
from revcan.reverse_engineering.models.experiment import Experiment, Extern_Signal, Signal
from revcan.reverse_engineering.models.solutions import Solutions, Signal_Solution
import logging
from tqdm import tqdm
from copy import deepcopy
from bisect import bisect_left


def fast_groundtruth_lookup(timestamps, values, timestamp):
    pos = bisect_left(timestamps, timestamp)

    if pos == 0:
        return values[0]
    elif pos == len(timestamps):
        return values[-1]
    else:
        before = timestamps[pos - 1]
        after = timestamps[pos]
        return values[pos - 1] if abs(before - timestamp) <= abs(after - timestamp) else values[pos]

def construct_system (measured_signal: Signal, ground_truth_signal: Extern_Signal, datatype,  start_byte:int, length:int):
    

    timestamps = [v.time for v in ground_truth_signal.values]
    ground_values = [v.value for v in ground_truth_signal.values]

    values = measured_signal.values
    n = len(values)
    
    # Preallocate memory for efficiency
    x_raw = np.empty((n, length), dtype=np.uint8)
    y = np.empty(n)
    try:
        for i, v in enumerate(values):
            x_raw[i]= v.value[start_byte:start_byte+length]
            y[i]=(fast_groundtruth_lookup(timestamps,ground_values, v.time)[0])
    
        x = x_raw.view(datatype).ravel()
        y= np.array(y)
        X = np.vstack([x, np.ones(len(x))]).T
        return x, X , y
    except Exception as e:
        print(f"Error with signal: {measured_signal} datatye: {datatype} start byte:{start_byte} length: {length}")
        raise np.linalg.LinAlgError(str(e))
    


def solver ( measured_signal: Signal, ground_truth_signal: Extern_Signal, datatypes:List[str], start_byte:int, length:int):
    all_solutions= Solutions()
    for type in datatypes:
            try:
                x, X,y = construct_system(measured_signal, ground_truth_signal, type, start_byte, length)
                coefficients, residuals, rank, singular_values = np.linalg.lstsq(X ,y, rcond=None)
                if len(residuals) != 0:
                    all_solutions.solutions.append(Signal_Solution(
                        x=x,
                        y=y,
                        datatype=type,
                        coefficients=coefficients,
                        residuals=residuals,
                        rank=rank,
                        singular_values=singular_values,
                        serverid=measured_signal.serverid,
                        did=measured_signal.did.did,
                        start_byte=start_byte,
                        length=length,
                        )
                    )
            except np.linalg.LinAlgError:
                    pass
    return all_solutions       

def solver_task(args)    :
    signal, ext_meas, data_type, index, length = args
    return solver(signal, ext_meas, data_type, index, length)

def experiment_analysis(experiment_file_path: str, output_file_path: str, silent = True, number_of_processes:int=0):
    try:
        experiment = Experiment.load(experiment_file_path)
    except FileNotFoundError:
        print(f"Error: The experiment model file at '{experiment_file_path}' was not found.")
        return
    except Exception as e:
        print(f"Error loading experiment model: {e}")
        return

    if number_of_processes == 0:
        number_of_processes = multiprocessing.cpu_count()-1

    all_solutions= Solutions(groundtruth = experiment.external_measurements[0])
    

    data_types_1 = ['<u1','<i1','>u1','>i1']
    data_types_2 = ['<u2','<i2','<f2','>u2','>i2','>f2']
    data_types_4 = ['<u4','<i4','<f4','>u4','>i4','>f4']
    data_types_8 = ['<u8','<i8','<f8','>u8','>i8','>f8']

    number_of_systems = 0
    number_of_measurements = len(experiment.measurements)
    for i in range(0,number_of_measurements):
        signal = experiment.measurements[i]
        signal_length = len(signal.values[0].value)
        number_of_systems+= signal_length*4+(max(0,signal_length-1))*6+(max(0,signal_length-3))*6+(max(0,signal_length-7))*6    

    print(number_of_measurements)
    
    tasks = []    
    for i in range(number_of_measurements):
        
        signal = experiment.measurements[i]
        n = len(signal.values[0].value)

        ext_meas =(experiment.external_measurements[0])

        # length 1
        tasks += [( signal, ext_meas, data_types_1, x, 1) for x in range(n)]
        # length 2
        tasks += [( signal, ext_meas, data_types_2, x, 2) for x in range(n - 1)]
        # length 4
        tasks += [( signal, ext_meas, data_types_4, x, 4) for x in range(n - 3)]
        # length 8
        tasks += [( signal, ext_meas, data_types_8, x, 8) for x in range(n - 7)]

    print(f"Number of tasks: {len(tasks)}")
    all_solutions.save(output_file_path)
    
    with multiprocessing.Pool(number_of_processes) as pool:
         results = list(tqdm(pool.imap(solver_task,tasks,100 ), total=len(tasks)))

    for solutions in results:
        for sol in solutions.solutions:
            all_solutions.solutions.append(sol) 
    
    all_solutions.save(output_file_path)
   

if __name__ == "__main__":
    # Parse command-line arguments for configuration and experiment model paths
    argparser = argparse.ArgumentParser(
        description="Read data as defined in the experiment file"
    )
    argparser.add_argument(
        "--experiment_file_path",
        dest="experiment_file_path",
        type=str,
        help="Path to experiment file",
    )
    argparser.add_argument(
        "--output_file_path",
        dest="output_file_path",
        type=str,
        help="Path where output files are created",
    )

    argparser.add_argument(
        "--number_of_processes",
        dest="number_of_processes",
        type=int,
        default=0,
        help="Number of processes to run in parallel. Default 0 results in CPU-Cores-1",
    )

    argparser.add_argument(
        "--silent",
        dest="silent_flag",
        type=bool,
        help="Flag that indicates if the programm shall run silent,withtout print",
    )

    args = argparser.parse_args()

    experiment_analysis(args.experiment_file_path, args.output_file_path, args.silent_flag, args.number_of_processes)
