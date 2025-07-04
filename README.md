# Holistic Approach for Automated Reverse Engineering of Unified Diagnostics Service Data

This tool presents a holistic methodology that identifies signals without physically manipulating the vehicle. Our equipment is connected to the vehicle via the On-Board Diagnostics (OBD)-II port and uses the Unified Diagnostics Service (UDS) protocol to communicate with the vehicle. We access, capture, and analyze the vehicle’s signals for future analysis.

## Developer

The main developer of this tool is Nico Rosenberger (Institute for Automotive Technology, Technical University of Munich).

The below stated reference is the main documentation for the tool documented in this repositiory.

There are several other contributors who worked on different modules of the tool. Here follows an overviews of the contributors (in alphabetical order):

- Hoffmann, Nikolai (Master Thesis at the Technical University of Munich)
- Mitscherlich, Alexander (Master Thesis at the Technical University of Munich)

## Scope of this tool

Reverse engineering of the internal vehicle communication is a crucial discipline in vehicle benchmarking. The process presents a time-consuming procedure associated with high manual effort. Car manufacturers use unique signal addresses and encodings for their internal data. Accessing this data requires either expensive tools suitable for the respective vehicles or experienced engineers who have developed individual approaches to identify specific signals. The access to the internal data enables reading the vehicle’s status, and thus, reducing the need for additional test equipment. This results in vehicles closer to their production status and does not require manipulating the vehicle under study, which prevents affecting future test results. The main focus of this approach is to reduce the cost of such an analysis and design a more efficient benchmarking process. This is a holistic approach, which, in addition to decoding the signals, also grants access to the vehicle’s data, which allows researchers to utilize state-of-the-art methodologies to analyze their vehicles under study by greatly reducing necessary experience, time, and cost.

## Sources

The tool is documented in the following scientific publication:

Das muss man dann UPDATEN
Rosenberger, N.; Fundel, M.; Bogdan, S.; Köning, L.; Kragt, P.; Kühberger, M.; Lienkamp, M. Scientific benchmarking: Engineering quality evaluation of electric vehicle concepts. e-Prime - Advances in Electrical Engineering, Electronics and Energy 2024, 9, 100746. 
https://doi.org/10.1016/j.prime.2024.100746.

## Features
* Create overview of all available ECUs and DIDs of a vehicle
* Execute guided experiments for signal gathering
* Use linear regression or machine learning to identify signals

## Project Structure
    ├── data           <- must be created by user, will automatically populate
    │
    ├── revcan         <- contains all code and Notebooks
    │   │
    │   ├── modules    <- contains required modules
    │   │
    │   ├── Notebooks  <- Jupyter notebooks which guide through the experiments and analysis function
    │   │
    │   ├── reverse_enigneering  <- contains pydantic data models and neural network structures
    │   │
    │   ├── scripts_for_doip_new <- contains all newly developed doip python scripts,
    │                               contains jupyter notebook which guides through vehicle discovery
    │                               START HERE!
    │                                
    │
    ├── config.yaml     <- contains VINs and IP-Addresses of vehicles under test
    │
    ├── CONTRIBUTING.md <- contains poetry how to
    │
    ├── poetry.lock     <- contains poetry config
    │
    ├── pyproject.toml  <- contains poetry config



# Dependencies
Dependencies are managed using poetry, the _DOIP_Reverse_Engineering_Pipeline.ipynb under revcan/scripts_for_diop_new will guide through the setup



