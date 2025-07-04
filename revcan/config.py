"""Handle configuration loading and access for the application."""
import os
from pathlib import Path
import yaml
from typing import Dict, Any, Optional

class DoIPConfig:
    def __init__(self, raw) -> None:
        self.interface = raw.get("interface")

class Config:
    """
    A class to handle configuration loading and access for the application.
    Usage:
        config = Config()
        value = config.get("key")

    Attributes:
        config (Dict[str, Any]): The loaded configuration data.
        doip (Optional[DoIPConfig]): The DoIP configuration if present in the config file.

    Methods:
        __init__(config_file: Optional[Path] = None) -> None:
            Initializes the Config object, loads the configuration from the specified file.
            If no file is specified, it will look for an environment variable REVCAN_CONFIG_FILE.
            If that is not set, it will default to the config.yaml file in the project directory.
        
        load_config(config_file: Path) -> Dict[str, Any]:
            Loads configuration from the specified YAML file.
        
        get(key: str) -> Any:
            Retrieves a value from the configuration using the specified key.
        
        get_all() -> Dict[str, Any]:
            Retrieves all configuration values.
    """
    file_path: Path

    def __init__(self, config_file_path: Optional[str] = None) -> None:
        if config_file_path is None:
            # Check environment variable for config file
            env_config = os.getenv("REVCAN_CONFIG_FILE")
            if env_config:
                self.file_path = Path(env_config)
            else:
                # Default config file (located in the top level project directory, along with the readme for example)
                self.file_path = Path(__file__).parents[1] / "config.yaml"
        else:
            try:
                self.file_path = Path(config_file_path)
            except Exception as e:
                print(f"Provided config_file_path incorrect: {config_file_path}. ERROR: {e}")
                return
        self.config = self.load_config(self.file_path)
        if not self.config:
            raise ValueError("No configuration found. Is the file empty?")
        if "doip" in self.config:
            self.doip = DoIPConfig(self.config.get("doip"))
        else:
            self.doip = None

    def load_config(self, config_file: Path) -> Dict[str, Any]:
        """Load configuration from specified YAML file."""
        if not config_file.is_file():
            raise FileNotFoundError(f"Config file not found: {config_file}")

        with open(config_file, "r", encoding="UTF-8") as file:
            return yaml.safe_load(file)

    def get(self, key: str) -> Any:
        """Get value from configuration."""
        keys = key.split(".")
        config_part = self.config
        for k in keys[:-1]:
            config_part = config_part.setdefault(k, {})
        return config_part[keys[-1]]
        return self.config.get(key)

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return self.config
    
    def set(self, key: str, value: Any) -> None:
        """Set a value in the configuration."""
        keys = key.split(".")
        config_part = self.config
        for k in keys[:-1]:
            config_part = config_part.setdefault(k, {})
        config_part[keys[-1]] = value
    
    def save(self, file_path: Optional[str] = None):
        if file_path:
            self.file_path = Path(file_path)

        try:
             with open(self.file_path, "w", encoding="utf-8") as file:
                yaml.dump(self.config, file, default_flow_style=False)
        except Exception as e:
            raise RuntimeError(f"Failed to save the config file: {e}")
    
