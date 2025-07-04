import struct
from udsoncan.Request import Request
from udsoncan.Response import Response
from udsoncan.BaseService import BaseService, BaseResponseData
from udsoncan.ResponseCode import ResponseCode
from udsoncan.exceptions import *
import udsoncan.tools as tools

from typing import Dict, Any, Union, List, cast


class ReadScalingDataByIdentifier(BaseService):
    _sid = 0x24

    supported_negative_response = [
        ResponseCode.IncorrectMessageLengthOrInvalidFormat,
        ResponseCode.ConditionsNotCorrect,
        ResponseCode.RequestOutOfRange,
        ResponseCode.SecurityAccessDenied,
    ]

    class ResponseData(BaseResponseData):
        def __init__(self):
            super().__init__(ReadScalingDataByIdentifier)

    class InterpretedResponse(Response):
        service_data: "ReadScalingDataByIdentifier.ResponseData"

    @classmethod
    def validate_didlist_input(cls, dids: Union[int, List[int]]) -> List[int]:
        if not isinstance(dids, int) and not isinstance(dids, list):
            raise ValueError(
                "Data Identifier must either be an integer or a list of integer"
            )

        if isinstance(dids, int):
            tools.validate_int(dids, min=0, max=0xFFFF, name="Data Identifier")

        if isinstance(dids, list):
            for did in dids:
                tools.validate_int(did, min=0, max=0xFFFF, name="Data Identifier")

        return [dids] if not isinstance(dids, list) else dids

    @classmethod
    def make_request(cls, didlist: Union[int, List[int]]) -> Request:
        """
        Generates a request for ReadDataByIdentifier

        :param didlist: List of data identifier to read.
        :type didlist: list[int]

        :raises ValueError: If parameters are out of range, missing or wrong type
        :raises ConfigError: If didlist contains a DID not defined in didconfig
        """

        didlist = cls.validate_didlist_input(didlist)

        req = Request(cls)
        req.data = struct.pack(">" + "H" * len(didlist), *didlist)  # Encode list of DID

        return req

    @classmethod
    def interpret_response(cls, response: Response) -> InterpretedResponse:
        raise NotImplementedError("Service is not implemented")
