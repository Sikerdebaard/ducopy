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
        conn.assert_hostname = self.hostname_resolver(url)
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

        # Configure SSLContext to ignore hostname verification
        ssl_context = ssl.create_default_context()

        if isinstance(verify, str):
            ssl_context.load_verify_locations(verify)
            self.verify = True
        else:
            self.verify = verify

        # Mount adapter with SSLContext to the session
        adapter = CustomHostNameCheckingAdapter(ssl_context, custom_host_mapping)
        self.mount("https://", adapter)

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
            logger.info("API key refreshed at {}", time.ctime(self.api_key_timestamp))

    def request(
        self, method: str, url: str, ensure_apikey: bool = True, *args: tuple, **kwargs: dict
    ) -> requests.Response:
        """
        Sends a request, automatically prepending the base URL to the given URL if it's relative.

        Args:
            method (str): The HTTP method for the request (e.g., 'GET', 'POST').
            url (str): The relative or absolute URL path for the request.

        Returns:
            Response: The HTTP response from the server.
        """
        if ensure_apikey:
            self._ensure_apikey()

        # Join the base URL with the provided URL path
        if not url.startswith("http"):
            url = urljoin(self.base_url, url)

        kwargs.setdefault("verify", self.verify)

        logger.debug("Sending {} request to URL: {}", method.upper(), url)

        try:
            response = super().request(method, url, *args, **kwargs)
            logger.info("Received {} response from {}", response.status_code, url)
            return response
        except requests.RequestException as e:
            logger.error("Request to {} failed with error: {}", url, e)
            raise
