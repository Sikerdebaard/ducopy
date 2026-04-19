# DucoPy

**DucoPy** is a Python library and CLI tool for controlling a **DucoBox** ventilation unit equipped with either a **DucoBox Connectivity Board** (modern API) or **Communication and Print Board** (legacy API). Using DucoPy, you can retrieve information and control settings of your DucoBox system directly from your Python environment or command line.

> **Note:** The Connectivity Board provides full API access with advanced features like logs, detailed action discovery, and configuration updates. The Communication and Print Board has a reduced feature set focused on core operations like retrieving node information and changing ventilation states.

## Features

### All Board Types
- Retrieve node information and details
- Get configuration settings for nodes
- Change ventilation operation states (AUTO, MANUAL, etc.)
- Output information in a structured or JSON format

### Connectivity Board Only
- Retrieve API version information and available endpoints
- Get detailed action metadata for nodes
- Monitor system logs
- Update node configuration programmatically
- Execute advanced actions (reboot, reset config, etc.)

## Installation

The easiest way to install DucoPy is through pip:

```bash
pip install ducopy
```

Alternatively, you can clone the repository and install manually:

```bash
git clone https://github.com/sikerdebaard/ducopy.git
cd ducopy
pip install .
```

### Additional Requirements

This project uses [Typer](https://typer.tiangolo.com/) for the CLI, [Loguru](https://github.com/Delgan/loguru) for logging, [Rich](https://github.com/Textualize/rich) for pretty-printing, and [Pydantic](https://docs.pydantic.dev/) for data validation. These will be installed automatically with the above command.

## Using the DucoPy Facade in Python

The `DucoPy` Python class provides a simple interface for interacting with the DucoBox API. Below is an example of how to use it:

### Example

```python
from ducopy.ducopy import DucoPy
from pydantic import HttpUrl

# Initialize the DucoPy client with the base URL of your DucoBox
# Use https:// for Connectivity Board, http:// for Communication/Print Board
base_url = "https://your-ducobox-ip"  # Replace with the actual IP
ducopy = DucoPy(base_url=base_url)

# Get nodes (works on all board types)
nodes = ducopy.get_nodes()
print(nodes.model_dump(mode='json'))

# Retrieve information for a specific node (works on all board types)
node_id = 1
node_info = ducopy.get_node_info(node_id=node_id)
print(node_info.model_dump(mode='json'))

# Get API information (Connectivity Board only)
# For Communication/Print Board, this will raise NotImplementedError
if not ducopy.client.is_legacy_api:
    api_info = ducopy.get_api_info()
    print(api_info)

# Close the DucoPy client connection when done
ducopy.close()
```

### Available Methods

Here is a list of the main methods available in the `DucoPy` facade:

#### Supported on All Board Types
- `get_info(module: str | None = None, submodule: str | None = None, parameter: str | None = None) -> dict`: Retrieve information about modules and parameters.
- `get_nodes() -> NodesInfoResponse`: Retrieve a list of all nodes in the DucoBox system.
- `get_node_info(node_id: int) -> NodeInfo`: Get details about a specific node by its ID.
- `get_config_node(node_id: int) -> ConfigNodeResponse`: Get configuration settings for a specific node.
- `change_action_node(action: str, value: str, node_id: int) -> ActionsChangeResponse`: Change node state (limited to operation state changes on Communication/Print Board).

#### Connectivity Board Only
- `get_api_info() -> dict`: Retrieve general API information.
- `get_action(action: str | None = None) -> dict`: Retrieve information about a specific action.
- `get_actions_node(node_id: int, action: str | None = None) -> ActionsResponse`: Retrieve available actions for a specific node.
- `get_logs() -> dict`: Retrieve the system logs from the DucoBox.
- `update_config_node(node_id: int, config: ConfigNodeRequest) -> ConfigNodeResponse`: Update node configuration.

All methods return a dictionary or a Pydantic model instance. Use `.model_dump(mode='json')` on Pydantic models to get JSON-serializable output if needed.

## Using the CLI Client

DucoPy also provides a command-line interface (CLI) for interacting with your DucoBox system.

### CLI Commands

After installing DucoPy, you can access the CLI using the `ducopy` command:

```bash
ducopy --help
```

This will display a list of available commands.

### Example Commands

#### Available on All Board Types

1. **Get details about nodes**

   ```bash
   ducopy get-nodes https://your-ducobox-ip
   ```

2. **Get information for a specific node**

   ```bash
   ducopy get-node-info https://your-ducobox-ip --node-id 1
   ```

3. **Change node ventilation state**

   ```bash
   ducopy change-action-node https://your-ducobox-ip --node-id 1 --action OperState --value AUTO
   ```

#### Connectivity Board Only

4. **Retrieve API information**

   ```bash
   ducopy get-api-info https://your-ducobox-ip
   ```

5. **Get actions available for a node**

   ```bash
   ducopy get-actions-node https://your-ducobox-ip --node-id 1
   ```

6. **Retrieve system logs**

   ```bash
   ducopy get-logs https://your-ducobox-ip
   ```

### Output Formatting

All commands support an optional `--format` argument to specify the output format (`pretty` or `json`):

```bash
ducopy get-nodes https://your-ducobox-ip --format json
```

- `pretty` (default): Formats the output in a structured, readable style.
- `json`: Outputs raw JSON data, which can be useful for further processing or debugging.

### Logging Level

To set the logging level, use the `--logging-level` option, which accepts values like `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.

```bash
ducopy --logging-level DEBUG get-nodes https://your-ducobox-ip
```

## Contributing

We welcome contributions! Please open issues or submit pull requests on [GitHub](https://github.com/sikerdebaard/ducopy) to improve DucoPy.

## License

DucoPy is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

---

With **DucoPy**, you have a powerful tool at your fingertips to manage and control your DucoBox ventilation unit. Whether you're using the Python API or the CLI, DucoPy provides flexible, straightforward access to your system.