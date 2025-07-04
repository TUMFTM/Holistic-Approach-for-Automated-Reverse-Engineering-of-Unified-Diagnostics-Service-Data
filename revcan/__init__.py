import sys
from os.path import abspath, join, dirname

# Add the 'can_hacking/revcan/signal_discovery/utils' directory to the Python path
utils_path = abspath(join(dirname(__file__), "signal_discovery", "utils"))
signal_discovery_path = abspath(join(dirname(__file__), "signal_discovery"))
sys.path.insert(0, utils_path)
sys.path.insert(0, signal_discovery_path)

import udsoncan
import doipclient
