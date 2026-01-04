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
from pydantic import HttpUrl
from ducopy.rest.models import (
    ActionsResponse,
    NodeInfo,
    NodesResponse,
    ConfigNodeResponse,
    ConfigNodeRequest,
    ParameterConfig,
    NodesInfoResponse,
    ActionsChangeResponse,
    PYDANTIC_V2,
)
from ducopy.rest.utils import DucoUrlSession
from loguru import logger

import importlib.resources as pkg_resources
from ducopy import certs
import json


class APIClient:
    # Mapping of Connectivity Board endpoints to Communication and Print Board endpoints
    # Connectivity Board = modern API (family includes V1 and V2 boards)
    # Communication and Print Board = legacy API
    GEN1_ENDPOINT_MAP = {
        "/info": "/boxinfoget",
        "/api": "/boxinfoget",
        "/info/nodes": "/nodelist",
        "/config/nodes": "/boxinfoget",
    }
    # Pattern for node-specific endpoints (Connectivity Board -> Communication and Print Board)
    # /info/nodes/{id} -> /nodeinfoget?node={id}
    
    def __init__(self, base_url: HttpUrl, verify: bool = True, auto_detect: bool = True) -> None:
        self.base_url = base_url
        if verify:
            self.session = DucoUrlSession(base_url, verify=self._duco_pem(), endpoint_mapper=self._map_endpoint)
        else:
            self.session = DucoUrlSession(base_url, verify=verify, endpoint_mapper=self._map_endpoint)
        
        # API generation tracking
        self._api_version = None
        self._public_api_version = None
        self._generation = None
        self._board_type = None
        
        # Device identification cache (board-agnostic)
        self._mac_address = None
        self._board_serial = None
        self._device_info_cached = False
        
        logger.info("APIClient initialized with base URL: {}", base_url)
        
        # Automatically detect generation if requested
        if auto_detect:
            self.detect_generation()

    def _duco_pem(self) -> str:
        """Enable certificate pinning."""
        pem_path = pkg_resources.files(certs).joinpath("api_cert.pem")
        logger.debug("Using certificate at path: {}", pem_path)

        return str(pem_path)

    def detect_generation(self) -> dict:
        """
        Detect the API generation by trying HTTPS and HTTP with /info endpoint.
        
        This method determines whether we're communicating with:
        - Connectivity Board (modern API): HTTPS, /info endpoint exists
          Includes V1 and V2 variants
        - Communication and Print Board (legacy API): HTTP only, /info returns 404
        
        Detection logic:
        1. Try HTTPS with /info - if successful, it's Connectivity Board
        2. If HTTPS fails, try HTTP with /info
        3. If /info returns 404, it's Communication and Print Board
        4. If /info succeeds on HTTP, check version to determine board type
        
        Returns:
            dict: API information including version details and board type
        """
        logger.info("Detecting API generation...")
        
        # Check if we're using HTTPS
        is_https = str(self.base_url).startswith('https://')
        
        try:
            # Try to get /info endpoint directly (without mapping, without API key)
            logger.debug("Attempting to fetch /info endpoint...")
            response = self.session.request("GET", "/info", ensure_apikey=False)
            response.raise_for_status()
            info_response = response.json()
            
            # If we got here, /info exists
            if is_https:
                # HTTPS + /info exists = Connectivity Board (modern API)
                self._generation = "modern"
                self._board_type = "Connectivity Board"
                logger.info("Detected Connectivity Board (modern API) - HTTPS with /info endpoint")
            else:
                # HTTP + /info exists - need to check version
                logger.debug("Got /info on HTTP, checking version...")
                try:
                    api_response = self.session.request("GET", "/api", ensure_apikey=False)
                    api_response.raise_for_status()
                    api_info = api_response.json()
                    
                    self._api_version = api_info.get("ApiVersion", {}).get("Val")
                    self._public_api_version = api_info.get("PublicApiVersion", {}).get("Val")
                    
                    if self._public_api_version:
                        version_str = str(self._public_api_version)
                        if "2." in version_str:
                            self._generation = "modern"
                            self._board_type = "Connectivity Board"
                        elif "1." in version_str:
                            self._generation = "legacy"
                            self._board_type = "Communication and Print Board"
                        else:
                            self._generation = "unknown"
                            self._board_type = "Unknown Board"
                    else:
                        self._generation = "legacy"
                        self._board_type = "Communication and Print Board"
                except Exception:
                    # /info works but /api doesn't - assume modern
                    self._generation = "modern"
                    self._board_type = "Connectivity Board"
            
            logger.info(
                "API generation detected: {} (Protocol: {}, Board: {})",
                self._generation,
                "HTTPS" if is_https else "HTTP",
                self._board_type
            )
            
            # Warn if modern API is being accessed via HTTP
            if self._generation == "modern" and not is_https:
                logger.warning(
                    "Connectivity Board detected but connected via HTTP. "
                    "For better security, consider using HTTPS instead: https://{}", 
                    str(self.base_url).replace("http://", "").rstrip("/")
                )
            
            # Cache device identification info
            self._cache_device_info()
            
            return {
                "generation": self._generation,
                "api_version": self._api_version,
                "public_api_version": self._public_api_version,
                "protocol": "HTTPS" if is_https else "HTTP",
                "board_type": self._board_type,
                "mac_address": self._mac_address,
                "board_serial": self._board_serial
            }
            
        except Exception as e:
            error_message = str(e)
            
            # Check if it's a 404 error on /info
            if "404" in error_message:
                # /info returns 404 = Communication and Print Board (legacy API)
                self._generation = "legacy"
                self._board_type = "Communication and Print Board"
                logger.info("Detected Communication and Print Board (legacy API) - /info endpoint not found (404)")
                
                # Cache device identification info
                self._cache_device_info()
                
                return {
                    "generation": self._generation,
                    "api_version": None,
                    "public_api_version": None,
                    "protocol": "HTTPS" if is_https else "HTTP",
                    "board_type": self._board_type,
                    "mac_address": self._mac_address,
                    "board_serial": self._board_serial
                }
            
            # Check if it's a timeout or connection error with HTTPS
            if is_https and ("timeout" in error_message.lower() or "connection" in error_message.lower()):
                logger.warning("HTTPS connection failed. Communication and Print Board only supports HTTP.")
                raise ConnectionError(
                    "Failed to connect via HTTPS. The Communication and Print Board only supports HTTP connections. "
                    "Please use 'http://' instead of 'https://' in the URL."
                ) from e
            
            # Other error - connection failed or other issue
            logger.error("Failed to detect API generation: {}", e)
            self._generation = "unknown"
            raise

    @property
    def generation(self) -> str | None:
        """
        Get the detected API generation.
        
        Returns:
            str | None: 'modern', 'legacy', 'unknown', or None if not detected yet
        """
        return self._generation

    @property
    def api_version(self) -> str | None:
        """
        Get the full API version string.
        
        Returns:
            str | None: The API version or None if not detected yet
        """
        return self._api_version

    @property
    def public_api_version(self) -> str | None:
        """
        Get the public API version string.
        
        Returns:
            str | None: The public API version or None if not detected yet
        """
        return self._public_api_version

    @property
    def board_type(self) -> str | None:
        """
        Get the detected board type.
        
        Returns:
            str | None: 'Connectivity Board', 'Communication and Print Board', or None
        """
        return self._board_type

    @property
    def is_modern_api(self) -> bool:
        """
        Check if the board uses the modern API (Connectivity Board).
        
        The Connectivity Board family includes V1 and V2 variants.
        
        Returns:
            bool: True if Connectivity Board, False otherwise
        """
        return self._generation == "modern"

    @property
    def is_legacy_api(self) -> bool:
        """
        Check if the board uses the legacy API (Communication and Print Board).
        
        Returns:
            bool: True if Communication and Print Board, False otherwise
        """
        return self._generation == "legacy"

    @property
    def mac_address(self) -> str | None:
        """
        Get the cached MAC address of the device.
        
        This is fetched during detect_generation() and cached for consistent access
        regardless of board type:
        - Connectivity Board: Available in /info
        - Communication/Print Board: Available in /boardinfo
        
        Returns:
            str | None: The MAC address or None if not yet cached
        """
        return self._mac_address

    @property
    def board_serial(self) -> str | None:
        """
        Get the cached board serial number.
        
        This is fetched during detect_generation() and cached for consistent access
        regardless of board type.
        
        Returns:
            str | None: The board serial number or None if not yet cached
        """
        return self._board_serial

    def _cache_device_info(self) -> None:
        """
        Cache device identification information (MAC address, serial number).
        
        This method fetches device info from the appropriate endpoint based on board type:
        - Connectivity Board (modern): /info endpoint contains all info
        - Communication/Print Board (legacy): MAC is in /boardinfo endpoint
        
        The cached info is then available via properties for consistent access.
        """
        if self._device_info_cached:
            logger.debug("Device info already cached")
            return
        
        try:
            if self.is_modern_api:
                # Connectivity Board: /info has everything
                logger.debug("Fetching device info from /info endpoint (Connectivity Board)")
                response = self.session.request("GET", "/info", ensure_apikey=False)
                response.raise_for_status()
                data = response.json()
                
                # Extract MAC and serial from nested structure
                if "General" in data and "Lan" in data["General"]:
                    self._mac_address = data["General"]["Lan"].get("Mac", {}).get("Val")
                if "General" in data and "Board" in data["General"]:
                    self._board_serial = data["General"]["Board"].get("SerialBoardBox", {}).get("Val")
                
                logger.info("Cached device info from Connectivity Board: MAC={}, Serial={}", 
                           self._mac_address, self._board_serial)
                
            elif self.is_legacy_api:
                # Communication/Print Board: Need /boardinfo for MAC
                logger.debug("Fetching device info from /boardinfo endpoint (Communication/Print Board)")
                
                # Try /boardinfo endpoint for MAC and serial
                try:
                    response = self.session.request("GET", "/board_info", ensure_apikey=False)
                    response.raise_for_status()
                    board_data = response.json()
                    
                    # Communication/Print board /board_info returns plain values:
                    # {"serial": "PRSN21401066", "mac": "00:08:5f:35:a8:0f", "swversion": "16036.13.4.0", "uptime": 2452}
                    self._mac_address = board_data.get("mac")
                    self._board_serial = board_data.get("serial")
                    self._board_uptime = board_data.get("uptime")
                    
                    logger.info("Cached device info from Communication/Print Board: MAC={}, Serial={}, Uptime={}", 
                               self._mac_address, self._board_serial, self._board_uptime)
                    
                except Exception as e:
                    logger.warning("Failed to fetch /boardinfo endpoint: {}. Device info may be incomplete.", e)
                    # Continue - partial info is acceptable
            
            self._device_info_cached = True
            
        except Exception as e:
            logger.error("Failed to cache device info: {}", e)
            # Don't raise - this is not critical, just nice to have

    def _map_endpoint(self, endpoint: str) -> str:
        """
        Map Connectivity Board endpoints to Communication and Print Board equivalents if using legacy API.
        
        Args:
            endpoint: The Connectivity Board endpoint
            
        Returns:
            str: The appropriate endpoint for the current board type
        """
        # Don't map if generation hasn't been detected yet
        if self._generation is None:
            return endpoint
            
        if self.is_legacy_api:
            # Handle direct mappings
            if endpoint in self.GEN1_ENDPOINT_MAP:
                mapped = self.GEN1_ENDPOINT_MAP[endpoint]
                logger.debug("Mapped endpoint {} to Communication and Print Board endpoint: {}", endpoint, mapped)
                return mapped
            
            # Handle pattern-based mappings for node-specific endpoints
            # /config/nodes/{id} -> /nodeconfigget?node={id}
            if endpoint.startswith("/config/nodes/"):
                node_id = endpoint.split("/")[-1]
                mapped = f"/nodeconfigget?node={node_id}"
                logger.debug("Mapped endpoint {} to Communication and Print Board endpoint: {}", endpoint, mapped)
                return mapped
        
        return endpoint

    def _transform_gen1_info(self, gen1_data: dict) -> dict:
        """
        Transform Communication and Print Board info response to Connectivity Board format.
        Wraps all flat values in {"Val": value} structure to match modern API format.
        
        Args:
            gen1_data: Legacy API response data with flat structure
            
        Returns:
            dict: Transformed data with values wrapped in {"Val": value} format
        """
        def wrap_value(value):
            """Wrap a value in {"Val": value} format if not None."""
            if value is None:
                return None
            if isinstance(value, dict):
                # Recursively wrap nested dicts
                return {k: wrap_value(v) for k, v in value.items()}
            return {"Val": value}
        
        # Recursively wrap all values in the data structure
        return {k: wrap_value(v) for k, v in gen1_data.items()}
    
    def _transform_gen1_node_info(self, gen1_data: dict) -> dict:
        """
        Transform Communication and Print Board node info response to Connectivity Board NodeInfo format.
        
        Communication and Print Board format:
        {"node": 4, "devtype": "UNKN", "addr": 0, "state": "AUTO", "ovrl": 255, "cerr": 0, ...}
        
        Connectivity Board format:
        {"Node": 4, "General": {"Type": {"Val": "..."}, "Addr": 0}, "Ventilation": {...}, ...}
        """
        # Network-related fields that should go to NetworkDuco
        network_fields = {
            "subtype": "Subtype",
            "sub": "Sub",
            "prnt": "Prnt",
            "asso": "Asso",
            "rssi_n2m": "RssiN2M",
            "hop_via": "HopVia",
            "rssi_n2h": "RssiN2H",
            "show": "Show",
            "link": "Link",
        }
        
        # Extract all sensor fields (co2, temp, rh, etc.) - exclude snsr as it's metadata
        # Wrap values in {"Val": value} format to match Connectivity Board structure
        sensor_fields = {}
        # Map lowercase keys to proper capitalized names
        sensor_key_mapping = {
            "co2": "Co2",
            "temp": "Temp",
            "rh": "Rh"
        }
        known_sensor_keys = ["co2", "temp", "rh", "CO2", "Temp", "RH"]
        for key in known_sensor_keys:
            if key in gen1_data:
                normalized_key = key.lower()
                proper_key = sensor_key_mapping.get(normalized_key, normalized_key.capitalize())
                sensor_fields[proper_key] = {"Val": gen1_data[key]}
        
        # Also check for any other potential sensor fields by looking for numeric values
        # that aren't already captured in other sections
        known_non_sensor_keys = {"node", "devtype", "addr", "state", "ovrl", "cerr", "cntdwn", "endtime", "mode", "trgt", "actl", "snsr", "sw", "swver", "swversion", "serial", "serialboard", "serialnode", "serialnb"}
        known_non_sensor_keys.update(network_fields.keys())  # Exclude network fields
        for key, value in gen1_data.items():
            if key not in known_non_sensor_keys and isinstance(value, (int, float)):
                normalized_key = key.lower()
                proper_key = sensor_key_mapping.get(normalized_key, normalized_key.capitalize())
                sensor_fields[proper_key] = {"Val": value}
        
        # Remove zero values from sensor data (check the Val inside the dict)
        sensor_fields = {k: v for k, v in sensor_fields.items() if v.get("Val") != 0 and v.get("Val") != 0.0}
        
        # Extract software version (try multiple common field names)
        sw_version = None
        for sw_key in ["sw", "swver", "swversion"]:
            if sw_key in gen1_data and gen1_data[sw_key]:
                sw_version = {"Id": None, "Val": gen1_data[sw_key]}
                break
        
        # Extract serial number (try multiple common field names)
        serial_board = None
        for serial_key in ["serial", "serialboard", "serialnode", "serialnb"]:
            if serial_key in gen1_data and gen1_data[serial_key]:
                serial_board = gen1_data[serial_key]
                break
        
        # Build General section
        general_info = {
            "Type": {
                "Id": None,
                "Val": gen1_data.get("devtype", "UNKN")
            },
            "Addr": {"Val": gen1_data.get("addr", 0)} if gen1_data.get("addr") is not None else None
        }
        
        # Add SwVersion if available
        if sw_version:
            general_info["SwVersion"] = sw_version
        
        # Add SerialBoard if available
        if serial_board:
            general_info["SerialBoard"] = serial_board
        
        return {
            "Node": gen1_data.get("node"),
            "General": general_info,
            "NetworkDuco": {
                "CommErrorCtr": {"Val": gen1_data.get("cerr", 0)} if gen1_data.get("cerr") is not None else None,
                "Subtype": {"Val": gen1_data.get("subtype")} if gen1_data.get("subtype") is not None else None,
                "Sub": {"Val": gen1_data.get("sub")} if gen1_data.get("sub") is not None else None,
                "Prnt": {"Val": gen1_data.get("prnt")} if gen1_data.get("prnt") is not None else None,
                "Asso": {"Val": gen1_data.get("asso")} if gen1_data.get("asso") is not None else None,
                "RssiN2M": {"Val": gen1_data.get("rssi_n2m")} if gen1_data.get("rssi_n2m") is not None else None,
                "HopVia": {"Val": gen1_data.get("hop_via")} if gen1_data.get("hop_via") is not None else None,
                "RssiN2H": {"Val": gen1_data.get("rssi_n2h")} if gen1_data.get("rssi_n2h") is not None else None,
                "Show": {"Val": gen1_data.get("show")} if gen1_data.get("show") is not None else None,
                "Link": {"Val": gen1_data.get("link")} if gen1_data.get("link") is not None else None,
            } if gen1_data.get("cerr") is not None else None,
            "Ventilation": {
                "State": {"Val": gen1_data.get("state")} if gen1_data.get("state") else None,
                "FlowLvlOvrl": {"Val": gen1_data.get("ovrl", 0)} if gen1_data.get("ovrl") is not None else None,
                "TimeStateRemain": {"Val": gen1_data.get("cntdwn")} if gen1_data.get("cntdwn", 0) != 0 else None,
                "TimeStateEnd": {"Val": gen1_data.get("endtime")} if gen1_data.get("endtime", 0) != 0 else None,
                "Mode": {"Val": gen1_data.get("mode")} if gen1_data.get("mode") and gen1_data.get("mode") != "-" else None,
                "FlowLvlTgt": {"Val": gen1_data.get("trgt")} if gen1_data.get("trgt") is not None else None,
            } if any(k in gen1_data for k in ["state", "ovrl", "mode"]) else None,
            "Sensor": sensor_fields if sensor_fields else None,
        }

    def raw_get(self, endpoint: str, params: dict = None) -> dict:
        """
        Perform a raw GET request to the specified endpoint.

        Args:
            endpoint (str): The endpoint to send the GET request to (e.g., "/api").
            params (dict, optional): Query parameters to include in the request.

        Returns:
            dict: JSON response from the server.
        """
        # Map endpoint if using Communication and Print Board
        mapped_endpoint = self._map_endpoint(endpoint)
        
        logger.info("Performing raw GET request to endpoint: {} with params: {}", mapped_endpoint, params)
        response = self.session.get(mapped_endpoint, params=params)
        response.raise_for_status()
        logger.debug("Received response for raw GET request to endpoint: {}", mapped_endpoint)
        return response.json()

    def raw_post(self, endpoint: str, data: str | None = None) -> dict:
        """
        Perform a raw POST request to the specified endpoint with retry logic.

        Args:
            endpoint (str): The endpoint to send the POST request to (e.g., "/api").
            data (dict, optional): The data to include in the request body.
            params (dict, optional): Query parameters to include in the request.

        Returns:
            dict: JSON response from the server.
        """
        logger.info(f"Performing raw POST request to endpoint: {endpoint} with data: {data}")
        response = self.session.post(endpoint, json=data)
        response.raise_for_status()
        logger.debug("Received response for raw POST request to endpoint: {}", endpoint)
        return response.json()

    def raw_patch(self, endpoint: str, data: str | None = None) -> dict:
        """
        Perform a raw PATCH request to the specified endpoint with retry logic.

        Args:
            endpoint (str): The endpoint to send the PATCH request to (e.g., "/api").
            data (dict, optional): The data to include in the request body.
            params (dict, optional): Query parameters to include in the request.

        Returns:
            dict: JSON response from the server.
        """
        logger.info(f"Performing raw PATCH request to endpoint: {endpoint} with data: {data}")
        response = self.session.patch(endpoint, data=data)
        response.raise_for_status()
        logger.debug(f"Received response for raw PATCH request to endpoint: {endpoint}")
        return response.json()

    def post_action_node(self, action: str, value: str, node_id: int) -> ActionsChangeResponse:
        """
        Perform an action on a node.
        
        For Connectivity Board: POST to /action/nodes/{node_id} with JSON body
        For Communication and Print Board: GET to /nodesetoperstate?node={node_id}&value={value}

        Args:
            action (str): The action key (Connectivity Board only, ignored for Communication and Print Board).
            value (str): The value/state to set (e.g., 'AUTO', 'AUT1', 'MAN1', etc.).
            node_id (int): The ID of the node to perform the action on.

        Returns:
            ActionsChangeResponse: Response indicating success or failure.
        """
        # Communication and Print Board uses a simpler GET-based API
        if self.is_legacy_api:
            endpoint = "/nodesetoperstate"
            logger.info("Setting node {} operation state to {} (Communication and Print Board)", node_id, value)
            
            response = self.session.get(endpoint, params={"node": node_id, "value": value})
            response.raise_for_status()
            
            # Parse HTML response for SUCCESS or FAILURE/FAILED
            html_content = response.text.strip()
            if "SUCCESS" in html_content.upper():
                logger.info("Successfully changed node {} state to {}", node_id, value)
                # Return compatible response format
                return ActionsChangeResponse(Action=value, Result="Success")
            elif "FAIL" in html_content.upper():
                logger.error("Failed to change node {} state to {}: {}", node_id, value, html_content)
                raise ValueError(f"Failed to change node {node_id} state to {value}: {html_content}")
            else:
                logger.warning("Unexpected response from node state change: {}", html_content[:100])
                raise ValueError(f"Unexpected response from board: {html_content[:100]}")
        
        # Connectivity Board uses the modern POST API with validation
        # Fetch available actions for the node
        logger.info("Fetching available actions for node ID: {}", node_id)
        available_actions = self.get_actions_node(node_id=node_id)

        # Validate the action
        matching_action = next((a for a in available_actions.Actions if a.Action == action), None)
        if not matching_action:
            raise ValueError(
                f"Invalid action '{action}' for node {node_id}. Available actions: {[a.Action for a in available_actions.Actions]}"
            )

        # Validate the value
        if matching_action.ValType == "Enum":
            if value not in matching_action.Enum:
                raise ValueError(
                    f"Invalid value '{value}' for action '{action}'. Allowed values: {matching_action.Enum}"
                )
        elif matching_action.ValType == "Boolean":
            if value not in ["true", "false", "True", "False"]:
                raise ValueError(f"Invalid value '{value}' for action '{action}'. Allowed values: ['true', 'false']")
        elif matching_action.ValType == "Integer":
            try:
                int(value)
            except ValueError:
                raise ValueError(f"Invalid value '{value}' for action '{action}'. Expected an integer.")

        endpoint = f"/action/nodes/{node_id}"
        logger.info("Performing POST action with Action: {} and Val: {}", action, value)
        request_body = {"Action": action, "Val": value}
        # Without this, aka without removing space between the two key value pairs, it will return a 400 error
        serialized_body = json.dumps(request_body, separators=(",", ":"))

        response = self.session.post(endpoint, data=serialized_body)
        response.raise_for_status()
        logger.debug(
            "Received response for POST action from Node: {} with Action: {} and Val: {}", node_id, action, value
        )

        response_data = response.json()
        action_response = ActionsChangeResponse(**response_data)
        
        # Validate the response indicates success
        # Code should be 0 for success, non-zero for failure
        # Result should contain "SUCCESS" (case-insensitive)
        if action_response.Code is not None and action_response.Code != 0:
            logger.error("Action failed with error code {}: {}", action_response.Code, action_response.Result)
            raise ValueError(
                f"Failed to perform action '{action}' on node {node_id}. "
                f"Error code: {action_response.Code}, Result: {action_response.Result}"
            )
        
        if "SUCCESS" not in action_response.Result.upper():
            logger.error("Action failed with result: {}", action_response.Result)
            raise ValueError(
                f"Failed to perform action '{action}' on node {node_id}. Result: {action_response.Result}"
            )
        
        logger.info("Successfully performed action '{}' on node {} with value '{}'", action, node_id, value)
        return action_response

    def patch_config_node(self, node_id: int, config: ConfigNodeRequest) -> ConfigNodeResponse:
        """
        Update configuration settings for a specific node after validating the new values.

        Args:
            node_id (int): The ID of the node to update.
            config (ConfigNodeRequest): The configuration data to update.

        Returns:
            ConfigNodeResponse: The updated configuration response from the server.
        """
        if self.is_legacy_api:
            raise NotImplementedError(
                "Updating node configuration is not available on the Communication and Print Board. "
                "This feature is only available on the Connectivity Board."
            )
        
        logger.info("Updating configuration for node ID: {}", node_id)

        # Fetch current configuration of the node
        current_config_response = self.get_config_node(node_id)
        current_config = current_config_response.dict()

        # Validation logic (same as before)
        validation_errors = []
        for field, new_value in config.dict(exclude_unset=True).items():
            # Get current parameter configuration
            param_config_data = current_config.get(field)
            if param_config_data is None:
                error_message = f"Parameter '{field}' not available for node {node_id}."
                logger.error(error_message)
                validation_errors.append(error_message)
                continue

            # Create a ParameterConfig object
            param_config = ParameterConfig(**param_config_data)

            min_val = param_config.Min
            max_val = param_config.Max
            inc = param_config.Inc

            # Check if new_value is within Min and Max
            if min_val is not None and new_value < min_val:
                error_message = f"Value {new_value} for '{field}' is less than minimum {min_val}."
                logger.error(error_message)
                validation_errors.append(error_message)
            if max_val is not None and new_value > max_val:
                error_message = f"Value {new_value} for '{field}' is greater than maximum {max_val}."
                logger.error(error_message)
                validation_errors.append(error_message)

            # Check if new_value aligns with increment
            if inc is not None:
                base_value = min_val if min_val is not None else 0
                if (new_value - base_value) % inc != 0:
                    error_message = (
                        f"Value {new_value} for '{field}' is not a valid increment of {inc} starting from {base_value}."
                    )
                    logger.error(error_message)
                    validation_errors.append(error_message)

        if validation_errors:
            # Raise an exception with all validation errors
            raise ValueError("Validation errors:\n" + "\n".join(validation_errors))

        # Build the request body with 'Val' keys
        request_body = {}
        for field, new_value in config.dict(exclude_unset=True).items():
            request_body[field] = {"Val": new_value}

        # Send PATCH request if validation passes
        endpoint = f"/config/nodes/{node_id}"
        logger.info("Sending PATCH request with body: {}", request_body)
        response = self.session.patch(endpoint, json=request_body)
        response.raise_for_status()
        logger.debug("Updated config for node ID: {}", node_id)

        return self.get_config_node(node_id)

    def get_config_nodes(self) -> NodesResponse:
        """
        Retrieve the configuration settings for all nodes.

        Returns:
            NodesResponse: Parsed response containing configuration data for all nodes.
        """
        endpoint = "/config/nodes"
        logger.info("Fetching configuration for all nodes from endpoint: {}", endpoint)
        
        # Communication and Print Board doesn't have a /config/nodes endpoint - fetch each node individually
        if self._generation == "legacy":
            # First, get the node list - this will raise an exception if it fails
            nodes_response = self.get_nodes()
            node_configs = []
            failed_nodes = []
            node_ids = [node.Node for node in nodes_response.Nodes] if nodes_response.Nodes else []
            logger.info("Communication and Print Board detected - fetching config for {} nodes", len(node_ids))
            
            for node_id in node_ids:
                try:
                    config = self.get_config_node(node_id)
                    # ConfigNodeResponse and NodeConfig have the same fields, convert via dict
                    if PYDANTIC_V2:
                        node_configs.append(config.model_dump())
                    else:
                        node_configs.append(config.dict())
                except Exception as e:
                    logger.warning("Failed to fetch config for node {}: {}", node_id, e)
                    failed_nodes.append(node_id)
                    # Continue with other nodes - individual node failures are tolerated
            
            # If ALL nodes failed, raise an error - this indicates a systematic problem
            if failed_nodes and len(failed_nodes) == len(node_ids):
                raise RuntimeError(
                    f"Failed to fetch configuration for all {len(node_ids)} nodes. "
                    "This may indicate a communication problem with the board."
                )
            
            # If some nodes failed, log it but continue
            if failed_nodes:
                logger.warning(
                    "Successfully fetched config for {} of {} nodes. Failed nodes: {}", 
                    len(node_configs), len(node_ids), failed_nodes
                )
            
            data = {"Nodes": node_configs}
            return NodesResponse(**data)
        
        # Connectivity Board has the /config/nodes endpoint
        response = self.session.get(endpoint)
        response.raise_for_status()
        logger.debug("Received configuration data for all nodes")
        return NodesResponse(**response.json())  # Parse response into NodesResponse model

    def get_api_info(self) -> dict:
        """Fetch API version and available endpoints."""
        logger.info("Fetching API information")
        endpoint = self._map_endpoint("/api")
        response = self.session.get(endpoint)
        response.raise_for_status()
        logger.debug("Received API information")
        return response.json()

    def get_info(self, module: str = None, submodule: str = None, parameter: str = None) -> dict:
        """
        Fetch general API information.
        
        For Communication/Print boards, this method enriches the response with cached
        device identification info (MAC address, serial) that is only available via
        the /boardinfo endpoint, ensuring consistent data regardless of board type.
        """
        params = {k: v for k, v in {"module": module, "submodule": submodule, "parameter": parameter}.items() if v}
        
        # Map endpoint for Communication and Print Board
        endpoint = self._map_endpoint("/info")
        logger.info("get_info() called - generation: {}, using endpoint: {}", self._generation, endpoint)
        
        response = self.session.get(endpoint, params=params)
        response.raise_for_status()
        logger.debug("Received general info from endpoint: {}", endpoint)
        
        data = response.json()
        
        # Transform legacy API response to match modern API format
        if self._generation == "legacy":
            logger.debug("Transforming legacy info response to modern format")
            data = self._transform_gen1_info(data)
            
            # Enrich with cached device info (MAC, serial) for legacy boards
            # This info is only available in /communication endpoint on legacy boards
            if self._mac_address or self._board_serial:
                logger.debug("Enriching legacy board response with cached device info")
                
                # Ensure General structure exists
                if "General" not in data:
                    data["General"] = {}
                
                # Add Lan.Mac if cached
                if self._mac_address:
                    if "Lan" not in data["General"]:
                        data["General"]["Lan"] = {}
                    data["General"]["Lan"]["Mac"] = {"Val": self._mac_address}
                
                # Add Board.SerialBoardBox if cached
                if self._board_serial:
                    if "Board" not in data["General"]:
                        data["General"]["Board"] = {}
                    data["General"]["Board"]["SerialBoardBox"] = {"Val": self._board_serial}
        
        return data

    def get_nodes(self) -> NodesInfoResponse:
        """Retrieve list of all nodes."""
        logger.info("Fetching list of all nodes")
        endpoint = self._map_endpoint("/info/nodes")
        
        # This request must succeed - don't catch exceptions here
        # If it fails, let the exception propagate to the caller
        response = self.session.get(endpoint)
        response.raise_for_status()
        logger.debug("Received nodes data")
        
        data = response.json()
        
        # Communication and Print Board returns {"nodelist": [1, 2, 3]} instead of {"Nodes": [...]}
        # Fetch full info for each node to match Connectivity Board response structure
        if self._generation == "legacy" and "nodelist" in data:
            node_ids = data["nodelist"]
            nodes = []
            failed_nodes = []
            logger.info("Communication and Print Board detected - fetching details for {} nodes", len(node_ids))
            for node_id in node_ids:
                try:
                    node_info = self.get_node_info(node_id)
                    # Append the NodeInfo object directly, no need to convert to dict
                    nodes.append(node_info)
                except Exception as e:
                    logger.warning("Failed to fetch info for node {}: {}", node_id, e)
                    failed_nodes.append(node_id)
                    # Continue with other nodes - individual node failures are tolerated
            
            # If ALL nodes failed, raise an error - this indicates a systematic problem
            if failed_nodes and len(failed_nodes) == len(node_ids):
                raise RuntimeError(
                    f"Failed to fetch information for all {len(node_ids)} nodes. "
                    "This may indicate a communication problem with the board."
                )
            
            # If some nodes failed, log it but continue
            if failed_nodes:
                logger.warning(
                    "Successfully fetched {} of {} nodes. Failed nodes: {}", 
                    len(nodes), len(node_ids), failed_nodes
                )
            
            data = {"Nodes": nodes}
        elif self._generation == "modern" and "Nodes" in data:
            # Transform each node in the Connectivity Board response
            transformed_nodes = []
            for node in data["Nodes"]:
                transformed_node = self._transform_modern_node_info(node)
                transformed_nodes.append(transformed_node)
            data["Nodes"] = transformed_nodes
        
        return NodesInfoResponse(**data)

    def _normalize_node_structure(self, data: dict) -> dict:
        """
        Normalize and validate node data structure to ensure consistency.
        
        This method ensures that:
        1. All expected dict fields (General, NetworkDuco, Ventilation, Sensor) are dicts, not other types
        2. All values follow the {"Val": value} pattern where expected
        3. Invalid or unexpected types are corrected
        
        This provides a guaranteed consistent structure to integrations regardless of API quirks.
        """
        # Ensure General is a dictionary
        if "General" in data:
            if not isinstance(data["General"], dict):
                logger.warning("General field is type {} instead of dict, normalizing: {}", type(data["General"]).__name__, data["General"])
                # Convert invalid General to dict with Type field
                data["General"] = {"Type": {"Val": str(data["General"])}}
        
        # Ensure NetworkDuco is a dictionary or None
        if "NetworkDuco" in data:
            if data["NetworkDuco"] is not None and not isinstance(data["NetworkDuco"], dict):
                logger.warning("NetworkDuco field is type {} instead of dict, setting to None: {}", type(data["NetworkDuco"]).__name__, data["NetworkDuco"])
                data["NetworkDuco"] = None
        
        # Ensure Ventilation is a dictionary or None
        if "Ventilation" in data:
            if data["Ventilation"] is not None and not isinstance(data["Ventilation"], dict):
                logger.warning("Ventilation field is type {} instead of dict, setting to None: {}", type(data["Ventilation"]).__name__, data["Ventilation"])
                data["Ventilation"] = None
        
        # Ensure Sensor is a dictionary or None
        if "Sensor" in data:
            if data["Sensor"] is not None and not isinstance(data["Sensor"], dict):
                logger.warning("Sensor field is type {} instead of dict, setting to None: {}", type(data["Sensor"]).__name__, data["Sensor"])
                data["Sensor"] = None
        
        return data
    
    def _transform_modern_node_info(self, data: dict) -> dict:
        """
        Transform Connectivity Board node info response to move network fields to NetworkDuco.
        
        The Connectivity Board returns SubType, NetworkType, Parent, Asso in General section,
        but they should be in NetworkDuco section for consistency.
        """
        # First, normalize the structure to handle any API quirks
        data = self._normalize_node_structure(data)
        
        # Map modern API field names to model field names
        # Modern API uses: SubType, NetworkType, Parent, Asso
        # Model uses: Subtype, (no NetworkType stored separately), Prnt, Asso
        network_field_mapping = {
            "SubType": "Subtype",
            "Parent": "Prnt",
            "Asso": "Asso",
            # NetworkType is informational but not stored in the model currently
        }
        
        if "General" in data and isinstance(data["General"], dict):
            # Extract network fields from General
            network_data = {}
            for api_field, model_field in network_field_mapping.items():
                if api_field in data["General"]:
                    field_data = data["General"].pop(api_field)
                    # Extract the Val if it's a dict with Val key, otherwise use as-is
                    if isinstance(field_data, dict) and "Val" in field_data:
                        network_data[model_field] = field_data["Val"]
                    else:
                        network_data[model_field] = field_data
            
            # NetworkType is informational - can be logged but not stored in model
            if "NetworkType" in data["General"]:
                network_type = data["General"].pop("NetworkType")
                logger.debug("NetworkType: {}", network_type.get("Val") if isinstance(network_type, dict) else network_type)
            
            # Only create NetworkDuco section if we have network data
            if network_data:
                # Create or update NetworkDuco section
                if "NetworkDuco" not in data or data["NetworkDuco"] is None:
                    data["NetworkDuco"] = {}
                
                # Add network fields to NetworkDuco
                data["NetworkDuco"].update(network_data)
        
        # Normalize calibration data: Move Ventilation.Calibration.* to Calibration.Calib*
        # This ensures consistent access regardless of board type
        if "Ventilation" in data and isinstance(data["Ventilation"], dict):
            if "Calibration" in data["Ventilation"] and isinstance(data["Ventilation"]["Calibration"], dict):
                calib_data = data["Ventilation"].pop("Calibration")
                
                # Map Connectivity Board calibration fields to normalized names
                calib_mapping = {
                    "Valid": "CalibIsValid",
                    "State": "CalibState", 
                    "Error": "CalibError"
                }
                
                # Create Calibration section if it doesn't exist
                if "Calibration" not in data or data["Calibration"] is None:
                    data["Calibration"] = {}
                
                # Move and rename calibration fields
                for api_field, normalized_field in calib_mapping.items():
                    if api_field in calib_data:
                        data["Calibration"][normalized_field] = calib_data[api_field]
                
                logger.debug("Normalized calibration data from Ventilation.Calibration to Calibration section")
        
        return data

    def get_node_info(self, node_id: int) -> NodeInfo:
        """Retrieve detailed information for a specific node."""
        logger.info("Fetching info for node ID: {}", node_id)
        
        # Communication and Print Board uses /nodeinfoget?node=X instead of /info/nodes/X
        if self._generation == "legacy":
            endpoint = "/nodeinfoget"
            response = self.session.get(endpoint, params={"node": node_id})
        else:
            endpoint = self._map_endpoint(f"/info/nodes/{node_id}")
            response = self.session.get(endpoint)
        
        response.raise_for_status()
        logger.debug("Received node info for node ID: {}", node_id)
        
        data = response.json()
        
        # Transform responses to ensure consistent structure
        if self._generation == "legacy":
            data = self._transform_gen1_node_info(data)
        else:
            # Also transform modern API to move network fields to NetworkDuco
            data = self._transform_modern_node_info(data)
        
        return NodeInfo(**data)  # Direct instantiation for Pydantic 1.x

    def get_config_node(self, node_id: int) -> ConfigNodeResponse:
        """Retrieve configuration settings for a specific node."""
        logger.info("Fetching configuration for node ID: {}", node_id)
        endpoint = self._map_endpoint(f"/config/nodes/{node_id}")
        response = self.session.get(endpoint)
        response.raise_for_status()
        logger.debug("Received config for node ID: {}", node_id)
        return ConfigNodeResponse(**response.json())  # Direct instantiation for Pydantic 1.x

    def get_action(self, action: str = None) -> dict:
        """Retrieve action data."""
        if self.is_legacy_api:
            raise NotImplementedError(
                "Action retrieval is not available on the Communication and Print Board. "
                "This feature is only available on the Connectivity Board."
            )
        
        logger.info("Fetching action data for action: {}", action)
        params = {"action": action} if action else {}
        response = self.session.get("/action", params=params)
        response.raise_for_status()
        logger.debug("Received action data for action: {}", action)
        return response.json()

    def get_actions_node(self, node_id: int, action: str = None) -> ActionsResponse:
        """Retrieve available actions for a specific node."""
        if self.is_legacy_api:
            raise NotImplementedError(
                "Node actions are not available on the Communication and Print Board. "
                "This feature is only available on the Connectivity Board."
            )
        
        logger.info("Fetching actions for node ID: {} with action filter: {}", node_id, action)
        params = {"action": action} if action else {}
        response = self.session.get(f"/action/nodes/{node_id}", params=params)
        response.raise_for_status()
        logger.debug("Received actions for node ID: {}", node_id)
        return ActionsResponse(**response.json())  # Direct instantiation for Pydantic 1.x

    def get_logs(self) -> dict:
        """Retrieve API logs."""
        if self.is_legacy_api:
            raise NotImplementedError(
                "API logs are not available on the Communication and Print Board. "
                "This feature is only available on the Connectivity Board."
            )
        
        logger.info("Fetching API logs")
        response = self.session.get("/log/api")
        response.raise_for_status()
        logger.debug("Received API logs")
        return response.json()

    def get_board_info(self) -> dict:
        """
        Get board-level information including MAC address, serial number, and software version.
        
        This method provides a normalized interface for retrieving board information
        regardless of board type:
        
        - Connectivity Board: Queries /info endpoint (General.Board section)
        - Communication/Print Board: Queries /boardinfo for MAC/serial and finds BOX node for software version
        
        Returns:
            dict: Board information with the following structure:
                {
                    "Mac": str,           # MAC address (e.g., "AA:BB:CC:DD:EE:FF")
                    "Serial": str,        # Board serial number (e.g., "BOARD123456")
                    "SwVersion": str,     # Software version (e.g., "2.0.6.0" or "16010.3.7.0")
                    "Uptime": int,        # Board uptime in seconds (Communication/Print boards only, None for Connectivity)
                }
                
        Example:
            >>> client = APIClient("https://192.168.1.100")
            >>> board_info = client.get_board_info()
            >>> print(f"MAC: {board_info['Mac']}, Serial: {board_info['Serial']}, Version: {board_info['SwVersion']}")
        """
        logger.info("Fetching board information")
        
        if self.is_modern_api:
            # Connectivity Board: Get from /info endpoint
            logger.debug("Fetching board info from /info endpoint (Connectivity Board)")
            info = self.get_info()
            
            board_info = {
                "Mac": None,
                "Serial": None,
                "SwVersion": None,
                "Uptime": None
            }
            
            # Extract MAC address
            if "General" in info and "Lan" in info["General"]:
                mac_data = info["General"]["Lan"].get("Mac", {})
                if isinstance(mac_data, dict) and "Val" in mac_data:
                    board_info["Mac"] = mac_data["Val"]
                elif isinstance(mac_data, str):
                    board_info["Mac"] = mac_data
            
            # Extract serial number
            if "General" in info and "Board" in info["General"]:
                serial_data = info["General"]["Board"].get("SerialBoardBox", {})
                if isinstance(serial_data, dict) and "Val" in serial_data:
                    board_info["Serial"] = serial_data["Val"]
                elif isinstance(serial_data, str):
                    board_info["Serial"] = serial_data
            
            # Extract software version from Board section
            if "General" in info and "Board" in info["General"]:
                sw_data = info["General"]["Board"].get("SwVersion", {})
                if isinstance(sw_data, dict) and "Val" in sw_data:
                    board_info["SwVersion"] = sw_data["Val"]
                elif isinstance(sw_data, str):
                    board_info["SwVersion"] = sw_data
            
            logger.info("Retrieved Connectivity Board info: MAC={}, Serial={}, SwVersion={}", 
                       board_info["Mac"], board_info["Serial"], board_info["SwVersion"])
            
            return board_info
            
        else:
            # Communication/Print Board: Get from /boardinfo + BOX node
            logger.debug("Fetching board info from /boardinfo and BOX node (Communication/Print Board)")
            
            board_info = {
                "Mac": self._mac_address,
                "Serial": self._board_serial,
                "SwVersion": None,
                "Uptime": getattr(self, '_board_uptime', None)
            }
            
            # If not cached yet, try to fetch from /board_info
            if not self._device_info_cached:
                self._cache_device_info()
                board_info["Mac"] = self._mac_address
                board_info["Serial"] = self._board_serial
                board_info["Uptime"] = getattr(self, '_board_uptime', None)
            
            # Get software version from BOX node
            # Find the BOX node in the node list
            try:
                nodes = self.get_nodes()
                box_node = None
                
                # Look for a node with Type == "BOX"
                if nodes.Nodes:
                    for node in nodes.Nodes:
                        if node.General and node.General.Type and node.General.Type.Val == "BOX":
                            box_node = node
                            break
                
                if box_node and box_node.General.SwVersion:
                    if isinstance(box_node.General.SwVersion, dict) and "Val" in box_node.General.SwVersion:
                        board_info["SwVersion"] = box_node.General.SwVersion["Val"]
                    elif hasattr(box_node.General.SwVersion, "Val"):
                        board_info["SwVersion"] = box_node.General.SwVersion.Val
                    else:
                        board_info["SwVersion"] = str(box_node.General.SwVersion)
                    
                    logger.debug("Found BOX node (ID: {}) with SwVersion: {}", 
                               box_node.Node, board_info["SwVersion"])
                else:
                    logger.warning("BOX node not found or does not have SwVersion field")
                    
            except Exception as e:
                logger.warning("Failed to retrieve BOX node software version: {}", e)
            
            logger.info("Retrieved Communication/Print Board info: MAC={}, Serial={}, SwVersion={}", 
                       board_info["Mac"], board_info["Serial"], board_info["SwVersion"])
            
            return board_info

    def close(self) -> None:
        """Close the HTTP session."""
        logger.info("Closing the API client session")
        self.session.close()
