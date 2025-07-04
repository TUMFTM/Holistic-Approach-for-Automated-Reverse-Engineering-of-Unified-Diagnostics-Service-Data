import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import math
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import RobustScaler, StandardScaler, OneHotEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple, List
from revcan.reverse_engineering.models.experiment import Experiment

def train_signal_model(
        X_train, 
        y_train, 
        X_test, 
        y_test, 
        hidden_layers_config: List[int] = [64, 32],
        epochs=20, 
        batch_size=64):

    input_size = X_train.shape[1]
    
    # For regression, output_size = 1 if y is a single continuous value per sample
    output_size = y_train.shape[1] if len(y_train.shape) > 1 else 1

    layers = []
    prev_layer_size = input_size

    for layer_size in hidden_layers_config:
        layers.append(nn.Linear(prev_layer_size, layer_size))
        layers.append(nn.ReLU())
        prev_layer_size = layer_size

    layers.append(nn.Linear(prev_layer_size, output_size))
    model = nn.Sequential(*layers)

    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=1e-3)

    train_dataset = TensorDataset(X_train, y_train.float())
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    for epoch in range(epochs):
        model.train()
        for xb, yb in train_loader:
            pred = model(xb).squeeze()
            loss = criterion(pred, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    # Evaluation
    model.eval()
    with torch.no_grad():
        preds = model(X_test).squeeze()

        mse = nn.functional.mse_loss(preds, y_test.float()).item()
        mae = nn.functional.l1_loss(preds, y_test.float()).item()
        ss_res = torch.sum((y_test - preds) ** 2)
        ss_tot = torch.sum((y_test - torch.mean(y_test)) ** 2)
        r2_score = 1 - ss_res / ss_tot if ss_tot != 0 else float('nan')

    return model, {
        "mse": mse,
        "mae": mae,
        "r2": r2_score.item() if torch.is_tensor(r2_score) else r2_score
    }



def load_data(experiment: Experiment) -> pd.DataFrame:
    grouped_data = defaultdict(list)

    # Map each sample index to a ground truth 
    ground_truths = [val.value[0] for val in experiment.external_measurements[0].values]

    for signal in experiment.measurements:
        server_id = signal.serverid
        did = signal.did.did

        for value_obj, gt in zip(signal.values, ground_truths):
            if gt is not None:
                grouped_data[(server_id, did, gt)].append(value_obj.value)

    # Create structured rows
    data_records = []
    for (server_id, did, gt), values in grouped_data.items():
        data_records.append([server_id, did, gt] + values)

    # Determine the max number of values to set the right number of columns
    max_values = max(len(record) - 3 for record in data_records)

    # Create column names dynamically
    columns = ["Server_ID", "DID", "Ground_Truth"] + [f"Value_{i+1}" for i in range(max_values)]

    # Convert to DataFrame
    df = pd.DataFrame(data_records, columns=columns)

    return df

def custom_train_test_split(df, train_set_percentage: int = 75):
    train_records = []
    test_records = []
    
    for _, row in df.iterrows():
        server_id, did, ground_truth = row["Server_ID"], row["DID"], row["Ground_Truth"]
        
        # Extract values
        values = row.iloc[3:].values
        # Shuffle values
        np.random.shuffle(values)  
        total_values = len(values)
        train_count = math.ceil(total_values * train_set_percentage / 100) 

        # Assign at least train_set_percentage % of the data to train set, rest to test set
        for i in range(train_count):
            train_records.append([server_id, did, ground_truth, values[i]])
        for i in range(train_count, total_values):
            test_records.append([server_id, did, ground_truth, values[i]])

    # Convert to DataFrames
    train_df = pd.DataFrame(train_records, columns=["Server_ID", "DID", "Ground_Truth", "Value"])
    test_df = pd.DataFrame(test_records, columns=["Server_ID", "DID", "Ground_Truth", "Value"])

    return train_df, test_df


def split_df_by_signal(df: pd.DataFrame) -> Dict[Tuple[int, int], pd.DataFrame]:
    signal_dfs = {}

    grouped = df.groupby(["Server_ID", "DID"])
    for (server_id, did), group in grouped:
        selected_cols = ["Ground_Truth"] + ["Value"]
        cleaned_df = group[selected_cols].reset_index(drop=True)

        signal_dfs[(server_id, did)] = cleaned_df

    return signal_dfs

def expand_signal_df(df: pd.DataFrame, pad_value: int = np.nan) -> pd.DataFrame:
    values = df["Value"].to_list()

    # Get the max length of any value list in this signal
    max_len = max(len(v) for v in values)

    # Pad all value lists to the same length
    padded_values = [v + [pad_value] * (max_len - len(v)) for v in values]

    # Create byte columns
    value_df = pd.DataFrame(padded_values, columns=[f"Byte_{i}" for i in range(max_len)])

    # Combine with Ground_Truth column
    return pd.concat([df[["Ground_Truth"]].reset_index(drop=True), value_df], axis=1)

def one_hot_encode_ground_truth(df: pd.DataFrame) -> pd.DataFrame:
    one_hot = pd.get_dummies(df["Ground_Truth"], prefix="GT")
    return pd.concat([one_hot, df.drop(columns=["Ground_Truth"])], axis=1)

# Function to preprocess data for PyTorch
def preprocess_signal_df(df: pd.DataFrame):
    X = df.drop(columns=["Ground_Truth"]).values
    y = df["Ground_Truth"].values

    # Optional: normalize X per signal
    X_mean = X.mean(axis=0)
    X_std = X.std(axis=0) + 1e-6  # avoid division by zero
    X = (X - X_mean) / X_std

    return torch.tensor(X, dtype=torch.float32), torch.tensor(y, dtype=torch.float32)

# Function to detect useless input
def is_useless_signal(df: pd.DataFrame, threshold=1e-5, tolerance=0.99):
    # Drop label columns
    feature_df = df.drop(columns=[col for col in df.columns if col.startswith("GT_")])
    
    # Keep only numeric columns
    feature_df = feature_df.select_dtypes(include=[np.number])

    # Convert to numpy
    features = feature_df.to_numpy()
    
    if features.shape[1] == 0:
        return True  # No usable features

    stds = np.std(features, axis=0)
    constant_ratio = np.mean(stds < threshold)
    return constant_ratio > tolerance

# Function to detect signals, that have the same byte value for more then ground truth value
def is_ambiguous_signal(df: pd.DataFrame, ground_truth_col: str = "Ground_Truth") -> bool:
    feature_cols = [col for col in df.columns if col != ground_truth_col]
    if not feature_cols:
        return True  # Not enough features to evaluate

    # Round ground truth values to a tolerance to avoid floating point quirks
    df[ground_truth_col] = df[ground_truth_col].round(6)

    # Build mapping: feature vector -> set of ground truths it appears with
    feature_to_targets = {}

    for _, row in df.iterrows():
        feature = tuple(row[feature_cols])
        target = row[ground_truth_col]

        if feature not in feature_to_targets:
            feature_to_targets[feature] = set()
        feature_to_targets[feature].add(target)

    # Check if any feature vector appears under more than one ground truth
    for targets in feature_to_targets.values():
        if len(targets) > 1:
            return True  # Found ambiguous feature vector

    return False  # All feature vectors are uniquely mapped




# Score function for weighting classification metrics
def score(
        metric, 
        accuracy_weight = 0.4,
        f1_weight = 0.2,
        precision_weight = 0.2,
        recall_weight = 0.2
        ):

    if accuracy_weight+f1_weight+precision_weight+recall_weight == 1.0:
        return (
            accuracy_weight * metric['accuracy'] +
            f1_weight * metric['f1'] +
            precision_weight * metric['precision'] +
            recall_weight * metric['recall']
        )
    else:
        print(f"Sum of weights is unequal to 1 - accuracy: {accuracy_weight}, f1: {f1_weight}, precision: {precision_weight}, recall: {recall_weight}")
        return 0

    
