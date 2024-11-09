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
    State: GeneralInfo
    FlowLvlOvrl: int = Field(...)

    @root_validator(pre=True)
    def validate_flow_lvl_ovrl(cls, values: dict[str, dict | str | int]) -> dict[str, dict | str | int]:
        values["FlowLvlOvrl"] = extract_val(values.get("FlowLvlOvrl", {}))
        return values


class SensorData(BaseModel):
    """Dynamically captures any sensor data using a dictionary."""

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
    Sensor: SensorData | None  # Dynamic handling of any sensor data


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
