from pydantic import BaseModel
from typing import List, Tuple, NamedTuple


class Service(BaseModel):
    id: int
    name: str = "Unknown service"


class Parameter(BaseModel):
    did: int
    length: int


class Server(BaseModel):
    id: int
    max_payload_length: int
    parameters: List[Parameter]
    discovery_complete_flag: bool = False
    first_unchecked_did_in_did_discovery: int = 0
    did_discovery_time_seconds: int = 0

    #DID data-parameter-definitions as per ISO Table C.1
    #DID F180

    BootSoftwareIdentificationDataIdentifier: str = ""
    # DID F181
    applicationSoftwareIdentificationDataIdentifier: str = ""
    # DID F182
    applicationDataIdentificationDataIdentifier: str = ""
    # DID F183
    bootSoftwareFingerprintDataIdentifier: str = ""
    # DID F184
    applicationSoftwareFingerprintDataIdentifier: str = ""
    # DID F185
    applicationDataFingerprintDataIdentifier: str = ""
    # DID F186
    ActiveDiagnosticSessionDataIdentifier: str = ""
    # DID F187
    vehicleManufacturerSparePartNumberDataIdentifier: str = ""
    # DID F188
    vehicleManufacturerECUSoftwareNumberDataIdentifier: str = ""
    # DID F189
    vehicleManufacturerECUSoftwareVersionNumberDataIdentier: str = ""
    # DID F18A
    systemSupplierIdentifierDataIdentifier: str = ""
    # DID F18B
    ECUManufacturingDateDataIdentifier: str = ""
    # DID F18C
    ECUSerialNumberDataIdentifier: str = ""
    # DID F18D
    supportedFunctionalUnitsDataIdentifier: str = ""
    # DID F18E
    VehicleManufacturerKitAssemblyPartNumberDataIdentifier: str = ""
    # DID F18F
    RegulationXSoftwareIdentificationNumbers: str = ""
    # DID F190
    VINDataIdentifier: str = ""
    # DID F191
    vehicleManufacturerECUHardwareNumberDataIdentifier: str = ""
    # DID F192
    systemSupplierECUHardwareNumberDataIdentifier: str = ""
    # DID F193
    systemSupplierECUHardwareVersionNumberDataIdentifier: str = ""
    # DID F194
    systemSupplierECUSoftwareNumberDataIdentifier: str = ""
    # DID F195
    systemSupplierECUSoftwareVersionNumberDataIdentifier: str = ""
    # DID F196
    exhaustRegulationOrTypeApprovalNumberDataIdentifier: str = ""
    # DID F197
    systemNameOrEngineTypeDataIdentifier: str = ""
    # DID F198
    repairShopCodeOrTesterSerialNumberDataIdentifier: str = ""
    # DID F199
    programmingDateDataIdentifier: str = ""
    # DID F19A
    calibrationRepairShopCodeOrCalibrationEquipmentSerialNumberDataIdentifier: str = ""
    # DID F19B
    calibrationDateDataIdentifier: str = ""
    # DID F19C
    calibrationEquipmentSoftwareNumberDataIdentifier: str = ""
    # DID F19D
    ECUInstallationDateDataIdentifier: str = ""
    # DID F19E
    ODXFileDataIdentifier: str = ""
    # DID F19F
    EntityDataIdentifier: str = ""


class Arbitration_pair(NamedTuple):
    ecu_logical_address: int # id of the ECU we want to request
    client_logical_address :int # id of our tester/client for which we expect the answer to be addresed to



class Car(BaseModel):
    vin: str
    model: str
    test_name: str = ""
    description: str = ""
    services: List[Service]
    servers: List[Server]
    arb_id_pairs: List[Arbitration_pair]
    ecu_logical_address: int
    client_logical_address: int
    first_unchecked_server_id_in_server_discovery: int
    server_discovery_time_seconds: int = 0
    @classmethod
    def create_empty_Car(cls):
        return Car(
            vin="",
            model="",
            client_logical_address=0,
            ecu_logical_address=0,
            arb_id_pairs=[],
            servers=[],
            services=[],
            first_unchecked_server_id_in_server_discovery = 0
            )
    @classmethod
    def load(cls, filePath: str):
        with open(filePath, "r") as f:
            return Car.model_validate_json(f.read())

    
    def save(self, filePath: str):
        with open(filePath, "w") as f:
            json = self.model_dump_json(serialize_as_any=True)
            f.write(json)

