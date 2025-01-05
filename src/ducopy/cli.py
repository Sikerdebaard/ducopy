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
from rich import print as rich_print
from rich.pretty import Pretty
from urllib.parse import urlparse

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
    if isinstance(data, BaseModel):  # Check if data is a Pydantic model instance
        data = data.dict()  # Use `.dict()` for JSON serialization

    if format == "json":
        typer.echo(json.dumps(data, indent=4))
    else:
        rich_print(Pretty(data))


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
        response = facade.get_config_nodes()
        print_output(response, format)
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
    """Retrieve general API information with optional filters."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_info(module=module, submodule=submodule, parameter=parameter), format)


@app.command()
def get_nodes(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve list of all nodes."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_nodes(), format)


@app.command()
def get_node_info(
    base_url: str, node_id: int, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve information for a specific node by ID."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_node_info(node_id=node_id), format)


@app.command()
def get_config_node(
    base_url: str, node_id: int, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve configuration settings for a specific node."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_config_node(node_id=node_id), format)


@app.command()
def get_action(
    base_url: str,
    action: str = None,
    format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty",
) -> None:
    """Retrieve action data with an optional filter."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_action(action=action), format)


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
    print_output(facade.get_actions_node(node_id=node_id, action=action), format)


@app.command()
def get_logs(
    base_url: str, format: Annotated[str, typer.Option(help="Output format: pretty or json")] = "pretty"
) -> None:
    """Retrieve API logs."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    print_output(facade.get_logs(), format)


def entry_point() -> None:
    """Entry point for the CLI."""
    app()  # Run the Typer app


if __name__ == "__main__":
    entry_point()
