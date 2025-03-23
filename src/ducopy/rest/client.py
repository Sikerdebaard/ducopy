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
import asyncio
import ssl
from ssl import SSLContext
from typing import Any
from urllib.parse import urljoin

import importlib.resources as pkg_resources

from aiohttp import (
    ClientResponseError,
    ClientConnectorDNSError,
    ServerDisconnectedError,
    ClientSession,
    ClientTimeout,
    TCPConnector,
)

from loguru import logger
from ducopy import certs


class AIORestClient:
    _base_url: str = ""

    def __init__(
        self,
        base_url: str,
        verify: bool = True,
    ):
        self._base_url = base_url
        logger.debug(f'Using base_url "{base_url}"')

        ssl_context = ssl.create_default_context()

        if verify:
            # Configure SSLContext to ignore hostname verification
            # This is necessary because the PEM hostname is set to
            #  192.168.4.1 while most connectivity boards have a
            #  different IP.
            pemfile = self._duco_pem()
            ssl_context.load_verify_locations(pemfile)
            ssl_context.check_hostname = False

            logger.debug(f'SSL certificate verification enabled using PEM file: "{pemfile}".')
        else:
            # Disable cert verification
            # THIS IS UNSAFE AND NOT RECOMMENDED!
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            logger.warning(
                "Certificate validation is DISABLED. This is insecure and not recommended for production environments."
                "Proceed with caution as it exposes the connection to potential security risks."
            )

        self._session = asyncio.run(self._get_client_session(ssl_context))

    async def _get_client_session(self, ssl_context: SSLContext) -> ClientSession:
        return ClientSession(connector=TCPConnector(ssl=ssl_context))

    def __del__(self) -> None:
        try:
            asyncio.run(self._close())
        except Exception as e:
            logger.warning(f"Error while closing session: {e}")
            asyncio.new_event_loop().run_until_complete(self._close())

    async def _close(self) -> None:
        try:
            await self._session.close()

        except Exception as e:
            logger.error(f"Error while closing session: {e}")

    def _duco_pem(self) -> str:
        """Used to enable certificate pinning."""
        pem_path = pkg_resources.files(certs).joinpath("api_cert.pem")
        logger.debug(f'Using certificate at path: "{pem_path}"')

        return str(pem_path)

    def get(self, *args: tuple, **kwargs: dict) -> dict[str, Any] | None:
        return asyncio.run(self.async_get(*args, **kwargs))

    async def async_get(self, endpoint: str, max_retries: int = 5) -> dict[str, Any] | None:
        retries = 0
        url = urljoin(self._base_url, endpoint)
        while retries < max_retries:
            try:
                async with self._session.get(
                    url,
                    # headers=self._headers,
                    timeout=ClientTimeout(total=20000, sock_connect=300),
                ) as response:
                    logger.debug(f"Response status: {response.status}")

                    if 500 <= response.status <= 599:
                        raise ClientResponseError(
                            request_info=response.request_info,
                            history=response.history,
                            status=response.status,
                            message="Service Unavailable",
                        )

                    else:
                        response.raise_for_status()

                    return await response.json()

            except ClientResponseError as e:
                if e.status in self._retriable_status_codes:
                    retries += 1
                    delay = 1 * (2 ** (retries - 1))  # Exponential backoff
                    logger.warning(f"Retry {retries}/{max_retries}: Waiting {delay:.2f} seconds ({e.status} received)")
                    await asyncio.sleep(delay)

                else:
                    raise  # Reraise for other HTTP errors

            except ClientConnectorDNSError as e:
                logger.error(f"DNS resolution error: {e}")
                raise e

            except ServerDisconnectedError as e:
                logger.error(f"Server disconnected error: {e}")
                retries += 1
                delay = 1 * (2 ** (retries - 1))
                logger.warning(f"Retry {retries}/{max_retries}: Waiting {delay:.2f} seconds ({e.message} received)")
                await asyncio.sleep(delay)

            except Exception as e:
                logger.error(f"{type(e)=}, Error fetching {url}: {e}")
                raise

        logger.warning(f"Failed to fetch {url} after {max_retries} retries.")
        return None
