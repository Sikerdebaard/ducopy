import typer
import sys
from typing import Any, Annotated
from pydantic import HttpUrl, ValidationError, BaseModel
from loguru import logger
from ducopy.ducopy import DucoPy
from rich import print as rich_print
from rich.pretty import Pretty
import json

app = typer.Typer(no_args_is_help=True)  # Show help if no command is provided


def setup_logging(level: str) -> None:
    """Configure loguru with the specified log level."""
    logger.remove()  # Remove any default handlers
    logger.add(sink=sys.stderr, level=level.upper())  # Add a new handler with the specified level


def validate_url(url: str) -> str:
    """Validate the provided URL as an HttpUrl."""
    try:
        url = HttpUrl(url)
    except ValidationError:
        typer.echo(f"Invalid URL: {url}")
        raise typer.Exit(code=1)

    return str(url)


def print_output(data: Any, format: str) -> None:  # noqa: ANN401
    """Print output in the specified format."""
    if isinstance(data, BaseModel):  # Check if data is a Pydantic model instance
        data = data.model_dump(mode="json")  # Use model_dump for JSON serialization

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
