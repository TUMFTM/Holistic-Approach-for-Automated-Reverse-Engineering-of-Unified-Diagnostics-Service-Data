import pyshark
import logging
import subprocess
import platform
import time
import threading


class NetworkActions:
    """
    This class is used to search for a vehicle on the network and establish a connection with it.
    Attributes:
        interface: str
        capture_filter: str
        ip_address: str
        ip_address_client: str
        logical_address: int
        vin: str
        capture: pyshark.LiveRingCapture
        connection_established: bool
    Methods:
        _start_capture: None
        _stop_capture: None
        _process_packet: bool
        _print_packet: None
        search_for_vehicle: bool
        get_local_ip_address: str
        get_interface_ip: bool
    """

    interface: str
    capture_filter = "udp port 13400 and ip"
    ip_address: str  # Local IP address
    ip_address_client: str  # Client IP address
    logical_address: int
    vin: str
    net_capture: pyshark.LiveRingCapture
    connection_established = False

    @classmethod
    def __init__(cls, interface, print_connection_status=False):
        if interface == "test":
            cls.ip_address = ""
            cls.ip_address_client = ""
            cls.logical_address = 0
            return None

        print("Network Action: Searching for vehicle")
        cls.interface = interface

        cls._start_capture()
        cls.connection_established = cls.search_for_vehicle()

        if print_connection_status:
            cls.get_connection_status()

    @classmethod
    def _start_capture(cls):
        try:
            cls.net_capture = pyshark.LiveRingCapture(
                interface=cls.interface, bpf_filter=cls.capture_filter
            )
            print("Please reconnect to start the capture..")
        except Exception as e:
            logging.error(f"Error starting capture: {e}")

    @classmethod
    def _stop_capture(cls):
        try:
            if cls.net_capture:
                cls.net_capture.close()
                print("Capture stopped")
        except Exception as e:
            logging.error(f"Error stopping capture: {e}")

    @classmethod
    def _process_packet(cls, packet):
        try:
            doip_header = packet.doip
            if doip_header and doip_header.type == "0x0004":
                cls.vin = doip_header.VIN
                cls.logical_address = doip_header.logical_address
                # convert the logical address to int if it is not already
                if not isinstance(cls.logical_address, int):
                    cls.logical_address = int(cls.logical_address, 16)
                cls.ip_address = packet.ip.src
                if all((cls.vin, cls.logical_address, cls.ip_address)):
                    cls._stop_capture()
                    return True
        except Exception as e:
            print(e)

    @classmethod
    def _print_packet(cls, packet):
        print(packet)

    @classmethod
    def search_for_vehicle(cls):
        for packet in cls.net_capture.sniff_continuously(packet_count=3):
            time.sleep(0.5)
            connection = cls._process_packet(packet)
            if connection:
                ip_address_client_available = cls.get_interface_ip()
                if connection and ip_address_client_available:
                    return True

    @classmethod
    def get_interface_ip(cls):
        try:
            while True:  # runs until the ip address is found
                # Run the 'ipconfig' command on Windows or 'ifconfig' on Unix-like systems
                command = (
                    ["ipconfig", cls.interface]
                    if platform.system() == "Windows"
                    else ["ifconfig", cls.interface]
                )
                result = subprocess.run(command, capture_output=True, text=True)

                # Check if the command was successful
                if result.returncode == 0:
                    # Extract the IPv4 address from the output

                    lines = result.stdout.split("\n")
                    for line in lines:
                        if "IPv4 Address" in line:  # On Windows, IPv4 Address is used
                            ip_address = line.split(":")[1].strip()
                            cls.ip_address_client = ip_address
                            return True
                        elif "inet " in line:  # On Unix-like systems, 'inet' is used
                            ip_address = line.split()[1]
                            cls.ip_address_client = ip_address
                            return True
                else:
                    print(f"Error: {result.stderr}")
                    return False

        except Exception as e:
            print(f"Error: {e}")
            return False

    @classmethod
    def get_connection_status(cls):
        if cls.connection_established:
            print(
                f"Fahrzeug-IP gefunden: {cls.ip_address}; Client-IP: {cls.ip_address_client}; Logische Adresse: {cls.logical_address}, VIN: {cls.vin}"
            )
        else:
            print("Network Action: No connection established")

    @classmethod
    def return_connection(cls):
        connection = {
            "ip_address": cls.ip_address,
            "ip_address_client": cls.ip_address_client,
            "logical_address": cls.logical_address,
            "vin": cls.vin,
        }
        return connection


if __name__ == "__main__":
    NetworkActions("enp0s31f6", print_connection_status=True)
