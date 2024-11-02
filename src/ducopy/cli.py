import typer
from pydantic import HttpUrl, ValidationError
from ducopy.ducopy import DucoPy

app = typer.Typer()


def validate_url(url: str) -> str:
    """Validate the provided URL as an HttpUrl."""
    try:
        url = HttpUrl(url)
    except ValidationError:
        typer.echo(f"Invalid URL: {url}")
        raise typer.Exit(code=1)

    return str(url)


@app.command()
def get_api_info(base_url: str) -> None:
    """Retrieve API information."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_api_info())


@app.command()
def get_info(base_url: str, module: str = None, submodule: str = None, parameter: str = None) -> None:
    """Retrieve general API information with optional filters."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_info(module=module, submodule=submodule, parameter=parameter))


@app.command()
def get_nodes(base_url: str) -> None:
    """Retrieve list of all nodes."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_nodes())


@app.command()
def get_node_info(base_url: str, node_id: int) -> None:
    """Retrieve information for a specific node by ID."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_node_info(node_id=node_id))


@app.command()
def get_config_node(base_url: str, node_id: int) -> None:
    """Retrieve configuration settings for a specific node."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_config_node(node_id=node_id))


@app.command()
def get_action(base_url: str, action: str = None) -> None:
    """Retrieve action data with an optional filter."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_action(action=action))


@app.command()
def get_actions_node(base_url: str, node_id: int, action: str = None) -> None:
    """Retrieve actions available for a specific node."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_actions_node(node_id=node_id, action=action))


@app.command()
def get_logs(base_url: str) -> None:
    """Retrieve API logs."""
    base_url = validate_url(base_url)
    facade = DucoPy(base_url)
    typer.echo(facade.get_logs())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
