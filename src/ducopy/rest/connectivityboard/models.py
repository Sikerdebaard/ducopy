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
# ensure pydantic 1 and 2 support since HA is in a transition phase
try:
    from pydantic import BaseModel, Field, root_validator

    PYDANTIC_V2 = False
except ImportError:
    from pydantic import BaseModel, Field, model_validator

    PYDANTIC_V2 = True

from typing import Any, Literal
from functools import wraps


def unified_validator(*uargs, **ukwargs):  # noqa: ANN201, ANN002, ANN003
    """
    A unified validator decorator for Pydantic 1.x and 2.x.
    Ensures that user-defined validators run before field-level validation,
    allowing data transformations to occur first (e.g. extracting `.Val`).
    """

    def decorator(user_func):  # noqa: ANN001, ANN202
        """
        `user_func` is the actual validation function (e.g. `def validate_something(cls, values): ...`)
        """

        @wraps(user_func)
        def wrapper(cls, values):  # noqa: ANN202, ANN001
            # Call the user function to transform 'values' as needed
            return user_func(cls, values)

        if PYDANTIC_V2:
            # For Pydantic 2.x, we must set mode="before" to run prior to field validation
            ukwargs.setdefault("mode", "before")
            return model_validator(*uargs, **ukwargs)(wrapper)
        else:
            # For Pydantic 1.x, we must set pre=True to run prior to field validation
            ukwargs.setdefault("pre", True)
            return root_validator(*uargs, **ukwargs)(wrapper)

    return decorator


# Helper function to extract `Val` from nested dictionaries
def extract_val(data: dict | str | int) -> str | int | dict:
    if isinstance(data, dict) and "Val" in data:
        return data["Val"]
    return data


class ParameterConfig(BaseModel):
    Id: int | None = Field(default=None)
    Val: int | str
    Min: int | None = None
    Max: int | None = None
    Inc: int | None = None

    @unified_validator()
    def ensure_keys(cls, values: dict) -> dict:
        # Ensure all expected keys are present, set to None if not
        keys = ["Id", "Val", "Min", "Max", "Inc"]
        return {key: values.get(key) for key in keys}


class NodeConfig(BaseModel):
    Node: int
    SerialBoard: str = Field(default="n/a")
    SerialDuco: str = Field(default="n/a")
    FlowLvlAutoMin: ParameterConfig | None = None
    FlowLvlAutoMax: ParameterConfig | None = None
    FlowMax: ParameterConfig | None = None
    FlowLvlMan1: ParameterConfig | None = None
    FlowLvlMan2: ParameterConfig | None = None
    FlowLvlMan3: ParameterConfig | None = None
    TimeMan: ParameterConfig | None = None
    Co2SetPoint: ParameterConfig | None = None
    RhSetPoint: ParameterConfig | None = None
    RhDetMode: ParameterConfig | None = None
    TempDepEnable: ParameterConfig | None = None
    ShowSensorLvl: ParameterConfig | None = None
    SwitchMode: ParameterConfig | None = None
    FlowLvlSwitch: ParameterConfig | None = None
    Name: ParameterConfig | None = None


class NodesResponse(BaseModel):
    Nodes: list[NodeConfig]


class GeneralInfo(BaseModel):
    Id: int | None = None
    Val: str


class NodeGeneralInfo(BaseModel):
    Type: GeneralInfo
    Addr: int = Field(...)

    @unified_validator()
    def validate_addr(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        values["Addr"] = extract_val(values.get("Addr", {}))
        return values


class NetworkDucoInfo(BaseModel):
    CommErrorCtr: int = Field(...)

    @unified_validator()
    def validate_comm_error_ctr(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        values["CommErrorCtr"] = extract_val(values.get("CommErrorCtr", {}))
        return values


class VentilationInfo(BaseModel):
    State: str | None = None
    FlowLvlOvrl: int = Field(...)
    TimeStateRemain: int | None = None
    TimeStateEnd: int | None = None
    Mode: str | None = None
    FlowLvlTgt: int | None = None

    @unified_validator()
    def validate_ventilation_fields(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        fields_to_extract = ["FlowLvlOvrl", "TimeStateRemain", "TimeStateEnd", "Mode", "FlowLvlTgt", "State"]

        # Define keyword mappings for transformations
        time_fields = [field for field in values if "time" in field.lower()]
        replace_dash_fields = ["Mode", "State"]

        # Extract `Val` from each optional field if it exists
        for field in fields_to_extract:
            if field in values:
                val = extract_val(values[field])
                # Replace 0 with None for 'time' fields
                if field in time_fields and val == 0:
                    values[field] = None
                # Replace '-' with None for fields like Mode and State
                elif field in replace_dash_fields and val == "-":
                    values[field] = None
                else:
                    values[field] = val
        return values


class SensorData(BaseModel):
    """Dynamically captures sensor data, including environmental sensors."""

    data: dict[str, int | float | str] | None = Field(default_factory=dict)

    @unified_validator()
    def extract_sensor_values(cls, values: dict[str, Any]) -> dict[str, Any]:
        # Iterate over all fields and extract their `Val` if they have it
        values["data"] = {key: extract_val(value) for key, value in values.items()}
        return values


class NodeInfo(BaseModel):
    Node: int
    General: NodeGeneralInfo
    NetworkDuco: NetworkDucoInfo | None
    Ventilation: VentilationInfo | None
    Sensor: SensorData | None = Field(default=None)


class NodesInfoResponse(BaseModel):
    Nodes: list[NodeInfo] | None = Field(default=None)


# ConfigNodeResponse for specific node configuration
class ConfigNodeResponse(BaseModel):
    Node: int
    SerialBoard: str = Field(default="n/a")
    SerialDuco: str = Field(default="n/a")
    FlowLvlAutoMin: ParameterConfig | None = None
    FlowLvlAutoMax: ParameterConfig | None = None
    FlowMax: ParameterConfig | None = None
    FlowLvlMan1: ParameterConfig | None = None
    FlowLvlMan2: ParameterConfig | None = None
    FlowLvlMan3: ParameterConfig | None = None
    TimeMan: ParameterConfig | None = None
    Co2SetPoint: ParameterConfig | None = None
    RhSetPoint: ParameterConfig | None = None
    RhDetMode: ParameterConfig | None = None
    TempDepEnable: ParameterConfig | None = None
    ShowSensorLvl: ParameterConfig | None = None
    SwitchMode: ParameterConfig | None = None
    FlowLvlSwitch: ParameterConfig | None = None
    Name: ParameterConfig | None = None


class ConfigNodeRequest(BaseModel):
    Name: str | None = None
    FlowLvlAutoMin: int | None = None
    FlowLvlAutoMax: int | None = None
    FlowMax: int | None = None
    FlowLvlMan1: int | None = None
    FlowLvlMan2: int | None = None
    FlowLvlMan3: int | None = None
    TimeMan: int | None = None
    Co2SetPoint: int | None = None
    RhSetPoint: int | None = None
    RhDetMode: int | None = None
    TempDepEnable: int | None = None
    ShowSensorLvl: int | None = None
    SwitchMode: int | None = None
    FlowLvlSwitch: int | None = None


class FirmwareResponse(BaseModel):
    Upload: dict[str, str | int]
    Files: list[dict[str, str | int]]


class ActionInfo(BaseModel):
    Action: str
    ValType: Literal["Enum", "Integer", "Boolean", "None"]
    Enum: list[str] | None  # Keep Enum optional

    @unified_validator()
    def set_optional_enum(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        """Set Enum only if ValType is Enum; ignore otherwise."""
        if values.get("ValType") != "Enum":
            values["Enum"] = None  # Ensure Enum is set to None if not required
        return values


class ActionsResponse(BaseModel):
    Node: int
    Actions: list[ActionInfo]
