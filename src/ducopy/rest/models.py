from pydantic import BaseModel, Field, root_validator
from typing import Literal, Any


# Helper function to extract `Val` from nested dictionaries
def extract_val(data: dict | str | int) -> str | int | dict:
    if isinstance(data, dict) and "Val" in data:
        return data["Val"]
    return data


# Define models with conditional validation for optional fields
class GeneralInfo(BaseModel):
    Id: int
    Val: str


class NodeGeneralInfo(BaseModel):
    Type: GeneralInfo
    Addr: int = Field(...)

    @root_validator(pre=True)
    def validate_addr(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        values["Addr"] = extract_val(values.get("Addr", {}))
        return values


class NetworkDucoInfo(BaseModel):
    CommErrorCtr: int = Field(...)

    @root_validator(pre=True)
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

    @root_validator(pre=True)
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

    data: dict[str, int | float | str] = Field(default_factory=dict)

    @root_validator(pre=True)
    def extract_sensor_values(cls, values: dict[str, Any]) -> dict[str, Any]:
        # Iterate over all fields and extract their `Val` if they have it
        values["data"] = {key: extract_val(value) for key, value in values.items()}
        return values


class NodeInfo(BaseModel):
    Node: int
    General: NodeGeneralInfo
    NetworkDuco: NetworkDucoInfo | None
    Ventilation: VentilationInfo | None
    Sensor: SensorData | None  # Includes environmental and other sensor data


class NodesResponse(BaseModel):
    Nodes: list[NodeInfo]


class ConfigNodeRequest(BaseModel):
    Name: str | None


class ConfigNodeResponse(BaseModel):
    Node: int
    FlowLvlMan1: dict[str, int] | None
    Name: str | None

    @root_validator(pre=True)
    def validate_name(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        values["Name"] = extract_val(values.get("Name", {}))
        return values


class FirmwareResponse(BaseModel):
    Upload: dict[str, str | int]
    Files: list[dict[str, str | int]]


class ActionInfo(BaseModel):
    Action: str
    ValType: Literal["Enum", "Integer", "Boolean", "None"]
    Enum: list[str] | None  # Keep Enum optional

    @root_validator(pre=True)
    def set_optional_enum(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        """Set Enum only if ValType is Enum; ignore otherwise."""
        if values.get("ValType") != "Enum":
            values["Enum"] = None  # Ensure Enum is set to None if not required
        return values


class ActionsResponse(BaseModel):
    Node: int
    Actions: list[ActionInfo]
