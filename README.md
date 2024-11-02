# DucoPy

**DucoPy** is a Python library and CLI tool that allows for full control of a **DucoBox** ventilation unit equipped with a **DucoBox Connectivity Board**. Using DucoPy, you can retrieve information, control settings, and monitor logs of your DucoBox system directly from your Python environment or command line.

## Features

- Retrieve API information from the DucoBox system
- Get details about available modules, nodes, actions, and logs
- Interact with specific nodes and configure them
- Control actions available on the DucoBox unit
- Output information in a structured or JSON format

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
base_url = "https://your-ducobox-ip"  # Replace with the actual IP
ducopy = DucoPy(base_url=base_url)

# Retrieve API information
api_info = ducopy.get_api_info()
print(api_info)

# Get nodes
nodes = ducopy.get_nodes()
print(nodes.model_dump(mode='json'))

# Retrieve information for a specific node
node_id = 1
node_info = ducopy.get_node_info(node_id=node_id)
print(node_info.model_dump(mode='json'))

# Close the DucoPy client connection when done
ducopy.close()
```

### Available Methods

Here is a list of the main methods available in the `DucoPy` facade:

- `get_api_info() -> dict`: Retrieve general API information.
- `get_info(module: str | None = None, submodule: str | None = None, parameter: str | None = None) -> dict`: Retrieve information about modules and parameters.
- `get_nodes() -> NodesResponse`: Retrieve a list of all nodes in the DucoBox system.
- `get_node_info(node_id: int) -> NodeInfo`: Get details about a specific node by its ID.
- `get_config_node(node_id: int) -> ConfigNodeResponse`: Get configuration settings for a specific node.
- `get_action(action: str | None = None) -> dict`: Retrieve information about a specific action.
- `get_actions_node(node_id: int, action: str | None = None) -> ActionsResponse`: Retrieve available actions for a specific node.
- `get_logs() -> dict`: Retrieve the system logs from the DucoBox.

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

1. **Retrieve API information**

   ```bash
   ducopy get-api-info --base-url https://your-ducobox-ip
   ```

2. **Get details about nodes**

   ```bash
   ducopy get-nodes --base-url https://your-ducobox-ip
   ```

3. **Get information for a specific node**

   ```bash
   ducopy get-node-info --base-url https://your-ducobox-ip --node-id 1
   ```

4. **Get actions available for a node**

   ```bash
   ducopy get-actions-node --base-url https://your-ducobox-ip --node-id 1
   ```

5. **Retrieve system logs**

   ```bash
   ducopy get-logs --base-url https://your-ducobox-ip
   ```

### Output Formatting

All commands support an optional `--output-format` argument to specify the output format (`pretty` or `json`):

```bash
ducopy get-nodes --base-url https://your-ducobox-ip --output-format json
```

- `pretty` (default): Formats the output in a structured, readable style.
- `json`: Outputs raw JSON data, which can be useful for further processing or debugging.

### Logging Level

To set the logging level, use the `--logging-level` option, which accepts values like `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`.

```bash
ducopy --logging-level DEBUG get-nodes --base-url https://your-ducobox-ip
```

## Contributing

We welcome contributions! Please open issues or submit pull requests on [GitHub](https://github.com/sikerdebaard/ducopy) to improve DucoPy.

## License

DucoPy is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

---

With **DucoPy**, you have a powerful tool at your fingertips to manage and control your DucoBox ventilation unit. Whether you're using the Python API or the CLI, DucoPy provides flexible, straightforward access to your system.