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
from pydantic import BaseModel, HttpUrl, ValidationError
import typer
from loguru import logger
import json
import sys
from typing import Any, Annotated
from ducopy.ducopy import DucoPy
from rich.console import Console
from rich.pretty import Pretty
from urllib.parse import urlparse
import pprint

from ducopy.rest.models import ConfigNodeRequest

app = typer.Typer(no_args_is_help=True)  # Show help if no command is provided


def setup_logging(level: str) -> None:
    """Configure loguru with the specified log level."""
    logger.remove()  # Remove any default handlers
    logger.add(sink=sys.stderr, level=level.upper())  # Add a new handler with the specified level


class URLModel(BaseModel):
    url: HttpUrl


def validate_url(url: str) -> str:
    """Validate the provided URL as an HttpUrl."""
    try:
        # Use a Pydantic model to validate the URL
        validated_url = URLModel(url=url).url
    except ValidationError:
        typer.echo(f"Invalid URL: {url}")
        raise typer.Exit(code=1)
    return str(validated_url)


def print_output(data: Any, format: str) -> None:  # noqa: ANN401
    """Print output in the specified format."""
    # Recursively convert Pydantic models to dicts
    def convert_to_dict(obj):
        if isinstance(obj, BaseModel):
            return obj.dict() if hasattr(obj, 'dict') else obj.model_dump()
        elif isinstance(obj, dict):
            return {k: convert_to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [convert_to_dict(item) for item in obj]
        return obj
    
    data = convert_to_dict(data)

    if format == "json":
        typer.echo(json.dumps(data, indent=4))
    else:
        # Use Rich Console with wider width to keep NetworkDuco and similar dicts on one line
        console = Console(width=200)
        console.print(Pretty(data, expand_all=False))


@app.callback()
def configure(
    logging_level: Annotated[
        str, typer.Option(help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", case_sensitive=False)
    ] = "INFO",
) -> None:
    """CLI client for interacting with DucoPy."""
    setup_logging(logging_level)


@app.command()
def raw_get(
    url: str,
    params: Annotated[str, typer.Option(help="Query parameters as a JSON string", default="{}")] = "{}",
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """
    Perform a raw GET request to a specified URL.

    Args:
        url (str): Full URL of the API endpoint (e.g., "https://api.example.com/api").
        params (str): Query parameters as a JSON string (e.g., '{"key": "value"}').
        format (str): Output format: pretty or json.
    """
    url = validate_url(url)
    parsed_url = urlparse(url)
    base_url = (
        f"{parsed_url.scheme}://{parsed_url.netloc}"  # Extract scheme and netloc (e.g., "https://api.example.com")
    )
    endpoint = parsed_url.path  # Extract the path (e.g., "/api/resource")

    try:
        # Parse the params JSON string into a dictionary
        query_params = json.loads(params)
    except json.JSONDecodeError:
        typer.echo("Invalid JSON string for query parameters.")
        raise typer.Exit(code=1)

    facade = DucoPy(base_url)
    try:
        response = facade.raw_get(endpoint=endpoint, params=query_params)
        print_output(response, format)
    except Exception as e:
        logger.error("Error performing raw GET request: {}", str(e))
        typer.echo(f"Failed to perform raw GET request: {e}")
        raise typer.Exit(code=1)


@app.command()
def raw_post(
    url: str,
    data: Annotated[str, typer.Option(help="Request body data as a JSON string")] = "{}",
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """
    Perform a raw POST request to a specified URL.

    Args:
        url (str): Full URL of the API endpoint (e.g., "https://api.example.com/api").
        data (str): Request body data as a JSON string (e.g., '{"key": "value"}').
        params (str): Query parameters as a JSON string (e.g., '{"key": "value"}').
        format (str): Output format: pretty or json.
    """
    url = validate_url(url)
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    endpoint = parsed_url.path

    try:
        # Parse the data and params JSON strings into dictionaries
        request_data = json.loads(data)
    except json.JSONDecodeError:
        typer.echo("Invalid JSON string for request data or query parameters.")
        raise typer.Exit(code=1)

    facade = DucoPy(base_url)
    try:
        response = facade.raw_post(endpoint=endpoint, data=request_data)
        print_output(response, format)
    except Exception as e:
        logger.error("Error performing raw POST request: {}", str(e))
        typer.echo(f"Failed to perform raw POST request: {e}")
        raise typer.Exit(code=1)


@app.command()
def raw_patch(
    url: str,
    data: Annotated[str, typer.Option(help="Request body data as a JSON string")] = "{}",
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """
    Perform a raw PATCH request to a specified URL.

    Args:
        url (str): Full URL of the API endpoint (e.g., "https://api.example.com/api").
        data (str): Request body data as a JSON string (e.g., '{"key": "value"}').
        format (str): Output format: pretty or json.
    """
    url = validate_url(url)
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    endpoint = parsed_url.path

    try:
        # Parse the data JSON strings
        # This ensures that we are sending valid JSON
        request_data = json.loads(data)  # noqa: F841
    except json.JSONDecodeError:
        typer.echo("Invalid JSON string for request data or query parameters.")
        raise typer.Exit(code=1)

    facade = DucoPy(base_url)
    try:
        response = facade.raw_patch(endpoint, data=data)
        print_output(response, format)
    except Exception as e:
        logger.error("Error performing raw PATCH request: {}", str(e))
        typer.echo(f"Failed to perform raw PATCH request: {e}")
        raise typer.Exit(code=1)


@app.command()
def change_action_node(
    base_url: str,
    node_id: int,
    action: Annotated[str, typer.Option(help="The action key (Connectivity Board only, use any value for Communication and Print Board)")],
    value: Annotated[str, typer.Option(help="The state/value to set (e.g., AUTO, MAN1, AUT1)")],
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """
    Change the action/state for a specific node.
    
    - Connectivity Board: Sends a POST request with JSON body to /action/nodes/{node_id}
    - Communication and Print Board: Sends a GET request to /nodesetoperstate?node={node_id}&value={value}

    Args:
        base_url (str): The base URL of the API.
        node_id (int): The ID of the node to perform the action on.
        action (str): The action key (used only for Connectivity Board validation).
        value (str): The state/value to set (e.g., AUTO, MAN1, AUT1, MAN2, AUT2, etc.).
        format (str): Output format: pretty or json.
    """
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    try:
        response = facade.change_action_node(action=action, value=value, node_id=node_id)
        print_output(response, format)
    except Exception as e:
        logger.error("Error changing node action for node {}: {}", node_id, e)
        typer.echo(f"Failed to change node action for node {node_id}: {e}")
        raise typer.Exit(code=1)


@app.command()
def update_config_node(
    base_url: str,
    node_id: int,
    config_json: Annotated[str, typer.Option(help="Configuration parameters as a JSON string")],
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """
    Update configuration settings for a specific node.

    Args:
        base_url (str): The base URL of the API.
        node_id (int): The ID of the node to update.
        config_json (str): Configuration parameters as a JSON string.
        format (str): Output format: pretty or json.
    """
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    try:
        config_data = json.loads(config_json)
        config = ConfigNodeRequest(**config_data)
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error("Invalid configuration data: {}", e)
        typer.echo(f"Invalid configuration data: {e}")
        raise typer.Exit(code=1)
    try:
        response = facade.update_config_node(node_id=node_id, config=config)
        print_output(response, format)
    except Exception as e:
        logger.error("Error updating configuration for node {}: {}", node_id, e)
        typer.echo(f"Failed to update configuration for node {node_id}: {e}")
        raise typer.Exit(code=1)


@app.command()
def get_config_nodes(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """
    Retrieve configuration settings for all nodes.

    Args:
        base_url (str): The base URL of the API.
        format (str): Output format: pretty or json.
    """
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    try:
        # Get generation info
        generation_info = {
            "generation": facade.client.generation,
            "board_type": facade.client.board_type,
            "api_version": facade.client.api_version,
            "public_api_version": facade.client.public_api_version,
            "is_modern_api": facade.client.is_modern_api,
            "is_legacy_api": facade.client.is_legacy_api,
        }
        
        # Get config data
        config_data = facade.get_config_nodes()
        
        # Combine both
        output = {
            "generation_info": generation_info,
            "config_nodes": config_data,
        }
        
        print_output(output, format)
    except Exception as e:
        logger.error("Error fetching configuration for all nodes: {}", str(e))
        typer.echo(f"Failed to fetch configuration for all nodes: {e}")
        raise typer.Exit(code=1)


@app.command()
def get_api_info(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve API information."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_api_info(), format)


@app.command()
def get_info(
    base_url: str,
    module: str = None,
    submodule: str = None,
    parameter: str = None,
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """Retrieve general API information with optional filters. Also displays API generation info."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    # Get the generation info
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    # Get the regular info
    info_data = facade.get_info(module=module, submodule=submodule, parameter=parameter)
    
    # Combine both
    output = {
        "generation_info": generation_info,
        "api_info": info_data,
    }
    
    print_output(output, format)


@app.command()
def get_nodes(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve list of all nodes."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    # Get generation info
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    # Get nodes data
    nodes_data = facade.get_nodes()
    
    # Combine both
    output = {
        "generation_info": generation_info,
        "nodes": nodes_data,
    }
    
    print_output(output, format)


@app.command()
def get_node_info(
    base_url: str, node_id: int, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve information for a specific node by ID."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    # Get generation info
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    # Get node info
    node_data = facade.get_node_info(node_id=node_id)
    
    # Combine both
    output = {
        "generation_info": generation_info,
        "node_info": node_data,
    }
    
    print_output(output, format)


@app.command()
def get_config_node(
    base_url: str, node_id: int, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve configuration settings for a specific node."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    # Get generation info
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    # Get config data
    config_data = facade.get_config_node(node_id=node_id)
    
    # Combine both
    output = {
        "generation_info": generation_info,
        "config": config_data,
    }
    
    print_output(output, format)


@app.command()
def get_action(
    base_url: str,
    action: str = None,
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """Retrieve action data with an optional filter."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    # Get generation info
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    # Get action data
    action_data = facade.get_action(action=action)
    
    # Combine both
    output = {
        "generation_info": generation_info,
        "action": action_data,
    }
    
    print_output(output, format)


@app.command()
def get_actions_node(
    base_url: str,
    node_id: int,
    action: str = None,
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """Retrieve actions available for a specific node."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    # Get generation info
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    # Get actions data
    actions_data = facade.get_actions_node(node_id=node_id, action=action)
    
    # Combine both
    output = {
        "generation_info": generation_info,
        "actions": actions_data,
    }
    
    print_output(output, format)


@app.command()
def get_logs(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve API logs."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_logs(), format)


@app.command()
def check_generation(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Check the board type (Connectivity Board or Communication and Print Board)."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    
    generation_info = {
        "generation": facade.client.generation,
        "board_type": facade.client.board_type,
        "api_version": facade.client.api_version,
        "public_api_version": facade.client.public_api_version,
        "is_modern_api": facade.client.is_modern_api,
        "is_legacy_api": facade.client.is_legacy_api,
    }
    
    print_output(generation_info, format)


def entry_point() -> None:
    """Entry point for the CLI."""
    app()  # Run the Typer app


if __name__ == "__main__":
    entry_point()
