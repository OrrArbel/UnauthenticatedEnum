import abc
import base64
from abc import ABC

import requests

from collectors.BaseNTLMCollector import BaseNTLMCollector
from collectors.CollectorOutput import CollectorOutput
from utils.utils import parse_ntlm_challenge
import logging

logger = logging.getLogger(__name__)
DUMMY_NEGOTIATION = "Negotiate TlRMTVNTUAABAAAAMZCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw=="

WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"


class WinrmBaseCollector(BaseNTLMCollector, ABC):
    def __init__(self, targets: list[str]):
        super().__init__(targets)

    def get_url(self, target: str) -> str:
        return f"{self.scheme}://{target}:{self.port}/wsman"

    @property
    @abc.abstractmethod
    def scheme(self) -> str:
        pass

    def collect_data(self, target: str) -> CollectorOutput | None:
        # Initiate session by preparing a POST request to winrm's url on the target
        s = requests.Session()

        req = requests.Request("POST", self.get_url(target), data="")
        prepped = req.prepare()

        # Add NTLM Negotiate data to headers (empty authentication - no username and password). The data is encoded in Base64.
        prepped.headers["Authorization"] = DUMMY_NEGOTIATION

        # Send the request and get the response
        try:
            response = s.send(prepped, verify=False)
        except Exception as e:
            logger.error(f"WinRM could not get response from target - {e}")
            return None

        # Extract the NTLM challenge by removing the "Negotiate" prefix and decoding from Base64
        if WWW_AUTHENTICATE_HEADER in response.headers:
            authentication_header_value = response.headers[WWW_AUTHENTICATE_HEADER]
            if "Negotiate" not in authentication_header_value:
                logger.error(
                    "WinRM authentication header does not contain Negotiate, error."
                )
                return None
            challenge_base64 = authentication_header_value.split("Negotiate").strip()[1]
            collector_output = parse_ntlm_challenge(base64.b64decode(challenge_base64))
            return collector_output
        else:
            logger.error("WinRM authentication header not found.")
            return None
