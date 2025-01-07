# “Commons Clause” License Condition v1.0
#
# The Software is provided to you by the Licensor under the License, as defined below, subject to the following condition.
#
# Without limiting other conditions in the License, the grant of rights under the License will not include, and the License does not grant to you, the right to Sell the Software.
#
# For purposes of the foregoing, “Sell” means practicing any or all of the rights granted to you under the License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or consulting/ support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the License must also include this Commons Clause License Condition notice.
#
# Software: ducopy
# License: MIT License
# Licensor: Thomas Phil
#
#
# MIT License
#
# Copyright (c) 2024 Thomas Phil
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
import requests
from requests.adapters import HTTPAdapter
import ssl
from urllib.parse import urljoin
from collections.abc import Callable
import time
from ducopy.rest.apikeygenerator import ApiKeyGenerator
from loguru import logger


# Map the URL to the expected hostname in the certificate
def custom_host_mapping(url: str) -> str:
    return "192.168.4.1"


class CustomHostNameCheckingAdapter(HTTPAdapter):
    def __init__(
        self, ssl_context: ssl.SSLContext, hostname_resolver: Callable[[str], str], *args: tuple, **kwargs: dict
    ) -> None:
        self.ssl_context = ssl_context
        self.hostname_resolver = hostname_resolver
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args: tuple, **kwargs: dict) -> None:
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn: requests.adapters.HTTPAdapter, url: str, verify: bool, cert: str | None) -> None:
        # conn.assert_hostname = self.hostname_resolver(url)
        conn.assert_hostname = False
        return super().cert_verify(conn, url, verify, cert)


class DucoUrlSession(requests.Session):
    def __init__(self, base_url: str, verify: bool | str = True) -> None:
        """
        Initializes the BaseUrlSession with a base URL and optional SSL verification setting.

        Args:
            base_url (str): The base URL to prepend to relative URLs.
            verify (bool | str): Path to the certificate or a boolean indicating SSL verification.
        """
        super().__init__()
        self.base_url = base_url

        if isinstance(verify, str):
            # Configure SSLContext to ignore hostname verification
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(verify)
            self.verify = True

            # Mount adapter with SSLContext to the session
            adapter = CustomHostNameCheckingAdapter(ssl_context, custom_host_mapping)
            self.mount("https://", adapter)
            self.mount("http://", adapter)
        else:
            self.verify = verify

        self.api_key: str | None = None
        self.api_key_timestamp: float = 0.0
        self.api_key_cache_duration: int = 60

        logger.info("Initialized DucoUrlSession for base URL: {}", base_url)

    def _ensure_apikey(self) -> None:
        """Refresh API key if expired or missing."""
        if not self.api_key or (time.time() - self.api_key_timestamp) > self.api_key_cache_duration:
            logger.debug("API key is missing or expired. Fetching a new one.")
            req = self.request("GET", "/info", ensure_apikey=False)
            req.raise_for_status()
            data = req.json()

            ducomac = data["General"]["Lan"]["Mac"]["Val"]
            ducoserial = data["General"]["Board"]["SerialBoardBox"]["Val"]
            ducotime = data["General"]["Board"]["Time"]["Val"]

            apigen = ApiKeyGenerator()
            self.api_key = apigen.generate_api_key(ducoserial, ducomac, ducotime)
            self.api_key_timestamp = time.time()

            self.headers.update({"Api-Key": self.api_key})
            logger.debug(f"Api-Key: {self.api_key}")
            logger.info("API key refreshed at {}", time.ctime(self.api_key_timestamp))

    def request(
        self, method: str, url: str, ensure_apikey: bool = True, *args: tuple, **kwargs: dict
    ) -> requests.Response:
        """
        Sends a request, automatically prepending the base URL to the given URL if it's relative.
        Implements an exponential backoff retry strategy (up to 5 attempts) on request failures.

        Args:
            method (str): The HTTP method for the request (e.g., 'GET', 'POST').
            url (str): The relative or absolute URL path for the request.
            ensure_apikey (bool): Whether to automatically ensure an API key is present/valid.

        Returns:
            Response: The HTTP response from the server.

        Raises:
            requests.RequestException: If all retry attempts fail or another request-related error occurs.
        """
        if ensure_apikey:
            self._ensure_apikey()

        # Join the base URL with the provided URL path
        if not url.startswith("http"):
            url = urljoin(self.base_url, url)

        kwargs.setdefault("verify", self.verify)

        max_retries = 5
        for attempt in range(max_retries):
            try:
                logger.debug(
                    "Sending {} request to URL: {} (attempt {}/{})", method.upper(), url, attempt + 1, max_retries
                )

                response = super().request(method, url, *args, **kwargs)
                response.raise_for_status()
                logger.info("Received {} response from {}", response.status_code, url)
                return response

            except requests.HTTPError as e:
                code = e.response.status_code
                if code == 503:
                    # board is likely overloaded with requests
                    logger.debug("Received http error code 503")
                    if not self._retry_with_backoff(attempt, max_retries, url, e):
                        raise e
                else:
                    raise e
            except requests.RequestException as e:
                if not self._retry_with_backoff(attempt, max_retries, url, e):
                    raise e

    def _retry_with_backoff(self, attempt: int, max_retries: int, url: str, error: Exception) -> bool:
        logger.error("Request to {} failed (attempt {}/{}). Error: {}", url, attempt + 1, max_retries, error)

        # If not on the last attempt, wait (2^attempt seconds), then retry
        if attempt < max_retries - 1:
            backoff_time = 2**attempt
            logger.warning("Retrying in {} seconds...", backoff_time)
            time.sleep(backoff_time)

            return True
        else:
            # After exhausting all retries
            return False
