from revcan.signal_discovery.utils.udsoncan.connections import BaseConnection


class DoIPClientUDSConnector(BaseConnection):
    """
    A udsoncan connector which uses an existing DoIPClient as a DoIP transport layer for UDS (instead of ISO-TP).

    :param doip_layer: The DoIP Transport layer object coming from the ``doipclient`` package.
    :type doip_layer: :class:`doipclient.DoIPClient<python_doip.DoIPClient>`

    :param name: This name is included in the logger name so that its output can be redirected. The logger name will be ``Connection[<name>]``
    :type name: string

    :param close_connection: True if the wrapper's close() function should close the associated DoIP client. This is not the default
    :type name: bool

    """

    def __init__(self, doip_layer, name=None, close_connection=False, timeout=None):
        BaseConnection.__init__(self, name)
        self._connection = doip_layer
        self._close_connection = close_connection
        self.opened = False
        self.timeout = timeout

    def open(self):
        self.opened = True

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self._close_connection:
            self._connection.close()
        self.opened = False

    def is_open(self):
        return self.opened

    def specific_send(self, payload):
        if self.timeout:
            self._connection.send_diagnostic(bytearray(payload), self.timeout)
        else:
            self._connection.send_diagnostic(bytearray(payload))

    def specific_send_no_response(self, payload):
        self._connection.send_diagnostic_no_response(bytearray(payload))

    def specific_wait_frame(self, timeout: float = 2):
        return bytes(self._connection.receive_diagnostic(timeout=timeout))

    def specific_wait_frame_complete_message(self, timeout: float = 2):
        return self._connection.receive_message(timeout=timeout)

    def empty_rxqueue(self):
        self._connection.empty_rxqueue()

    def empty_txqueue(self):
        self._connection.empty_txqueue()

    def change_address(self, new_logical_address):
        self._connection.change_ecu_logical_address(new_logical_address)
