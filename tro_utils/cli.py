"""Console script for tro_utils."""
import os
import sys

import click
from rich.console import Console
from rich.table import Table

from . import TRPAttribute
from .tro_utils import TRO

console = Console()

_TEMPLATES = {
    "default": {
        "description": "Default pretty template by Craig Willis",
        "filename": "default.jinja2",
    },
}


class StringOrPath(click.ParamType):
    """Custom parameter type to accept either a valid string or a file path."""

    name = "string_or_path"

    def __init__(self, templates=None):
        if templates is None:
            templates = {}
        self.valid_strings = templates.keys()

    def convert(self, value, param, ctx):
        # Check if the value is in the allowed string set
        if value in self.valid_strings:
            return value
        # Check if the value is a valid path
        elif os.path.exists(value) and os.path.isfile(value):
            return value
        else:
            self.fail(
                f"'{value}' is neither a valid option ({', '.join(self.valid_strings)}) "
                f"nor a valid file path.",
                param,
                ctx,
            )


@click.group()
@click.option(
    "--declaration",
    type=click.Path(),
    required=False,
    help="Path to the TRO declaration file",
)
@click.option(
    "--profile",
    envvar="TRS_PROFILE",
    type=click.Path(),
    required=False,
    help="Path to the TRS profile file",
)
@click.option(
    "--gpg-fingerprint",
    envvar="GPG_FINGERPRINT",
    type=click.STRING,
    required=False,
    help="GPG fingerprint for signing TRO",
)
@click.option(
    "--gpg-passphrase",
    envvar="GPG_PASSPHRASE",
    type=click.STRING,
    required=False,
    help="GPG passphrase for signing TRO",
)
@click.option(
    "--tro-creator",
    envvar="TRO_CREATOR",
    type=click.STRING,
    required=False,
    help="TRO creator (only used when creating a new TRO)",
)
@click.option(
    "--tro-name",
    envvar="TRO_NAME",
    type=click.STRING,
    required=False,
    help="TRO name (only used when creating a new TRO)",
)
@click.option(
    "--tro-description",
    envvar="TRO_DESCRIPTION",
    type=click.STRING,
    required=False,
    help="TRO description (only used when creating a new TRO)",
)
def cli(
    declaration,
    profile,
    gpg_fingerprint,
    gpg_passphrase,
    tro_creator,
    tro_name,
    tro_description,
):
    pass


@cli.command(help="Verify that TRO is signed and timestamped correctly")
@click.argument("declaration", type=click.Path(exists=True))
def verify_timestamp(declaration):
    tro = TRO(
        filepath=declaration,
    )
    tro.verify_timestamp()


@cli.command(help="Verify the integrity of the TRO")
@click.argument("declaration", type=click.Path(exists=True))
@click.argument(
    "package",
    type=click.Path(exists=True),
)
@click.option(
    "--arrangement-id",
    "-a",
    type=click.STRING,
    required=False,
    help="ID of the arrangement to verify. If not provided all arrangements will be tried",
)
@click.option(
    "--subpath",
    "-s",
    type=click.STRING,
    required=False,
    help="Subpath within the package structure, e.g. if arrangement is stored in a subdirectory",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed information during verification",
)
def verify_package(declaration, package, arrangement_id, subpath, verbose):
    subpath = subpath if subpath else ""
    tro = TRO(
        filepath=declaration,
    )
    if not arrangement_id:
        arrangements = [a["@id"] for a in tro.list_arrangements()]
    else:
        arrangements = [arrangement_id]

    for arrangement in arrangements:
        msg = (
            f"Verifying that arrangement '{arrangement}' matches package contents "
            f"of '{package}"
        )
        if subpath:
            msg += f"::{subpath}"
        msg += "'"
        click.echo(msg, nl=False)
        extra, mismatched, missing, success = tro.verify_replication_package(
            arrangement, package, subpath
        )
        if success:
            click.secho(" ✓", fg="green")
        else:
            click.secho(" ✗", fg="red")

        if extra and verbose:
            table = Table(
                title="[bold red]Extra Files Found[/bold red]", show_header=False
            )
            table.add_column("File", style="yellow")
            for e in extra:
                table.add_row(e)
            console.print(table)
            console.print()

        if mismatched and verbose:
            table = Table(title="[bold red]Mismatched Files Found[/bold red]")
            table.add_column("File", style="cyan")
            table.add_column("Expected Hash", style="green")
            table.add_column("Actual Hash", style="red")
            for filepath, expected_hash, actual_hash in mismatched:
                expected_display = (
                    expected_hash[:16] + "..." if expected_hash else "[dim]None[/dim]"
                )
                actual_display = (
                    actual_hash[:16] + "..." if actual_hash else "[dim]None[/dim]"
                )
                table.add_row(filepath, expected_display, actual_display)
            console.print(table)
            console.print()

        if missing and verbose:
            table = Table(
                title="[bold red]Missing Files Found[/bold red]", show_header=False
            )
            table.add_column("File", style="magenta")
            for m in missing:
                table.add_row(m)
            console.print(table)
            console.print()


@cli.group(help="Manage arrangements in the TRO")
def arrangement():
    pass


@cli.group(help="Manage compositions in the TRO")
def composition():
    pass


@cli.group(help="Manage perfomances in the TRO")
def performance():
    pass


@composition.command(help="Get info about current composition")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
@click.pass_context
def info(ctx, verbose):
    declaration = ctx.parent.parent.params.get("declaration")
    tro = TRO(
        filepath=declaration,
    )
    if verbose:
        data = {}
        for a in tro.list_arrangements():
            for c in a["trov:hasLocus"]:
                key = c["trov:hasArtifact"]["@id"]
                value = {"@id": c["@id"], "path": c["trov:hasLocation"]}
                if key not in data:
                    data[key] = [value]
                else:
                    data[key].append(value)

    for c in tro.get_composition_info()["trov:hasArtifact"]:
        print(c["@id"])
        print(f"  - mimeType: {c['trov:mimeType']}")
        print(f"  - sha256 {c['trov:sha256']}")
        if verbose:
            print("  - Arrangements:")
            for a in data.get(c["@id"], []):
                print(f"    - {a['path']} (id={a['@id']})")


@arrangement.command(help="Add a directory as a composition to the TRO")
@click.option("--comment", "-m", type=click.STRING, required=False)
@click.option("--ignore_dir", "-i", type=click.STRING, required=False, multiple=True)
@click.argument("directory", type=click.Path(exists=True))
@click.pass_context
def add(ctx, directory, ignore_dir, comment):
    ctx = ctx.parent.parent
    declaration = ctx.params.get("declaration")
    gpg_fingerprint = ctx.params.get("gpg_fingerprint")
    gpg_passphrase = ctx.params.get("gpg_passphrase")
    profile = ctx.params.get("profile")
    tro_name = ctx.params.get("tro_name")
    tro_description = ctx.params.get("tro_description")
    tro_creator = ctx.params.get("tro_creator")
    tro = TRO(
        filepath=declaration,
        gpg_fingerprint=gpg_fingerprint,
        gpg_passphrase=gpg_passphrase,
        profile=profile,
        tro_creator=tro_creator,
        tro_name=tro_name,
        tro_description=tro_description,
    )
    tro.add_arrangement(directory, ignore_dirs=ignore_dir, comment=comment)
    tro.save()


@arrangement.command(help="List available arrangements in the TRO")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
@click.pass_context
def list(ctx, verbose):
    declaration = ctx.parent.parent.params.get("declaration")
    tro = TRO(
        filepath=declaration,
    )
    for a in tro.list_arrangements():
        print(f"Arrangement(id={a['@id']}): {a['rdfs:comment']}")
        if verbose:
            print("  - Composition:")
            for c in a["trov:hasLocus"]:
                print(f"    - {c['trov:hasLocation']}")


@cli.command(help="Sign the TRO")
@click.pass_context
def sign(ctx):
    declaration = ctx.parent.params.get("declaration")
    gpg_fingerprint = ctx.parent.params.get("gpg_fingerprint")
    gpg_passphrase = ctx.parent.params.get("gpg_passphrase")
    profile = ctx.parent.params.get("profile")
    tro = TRO(
        filepath=declaration,
        gpg_fingerprint=gpg_fingerprint,
        gpg_passphrase=gpg_passphrase,
        profile=profile,
    )
    tro.request_timestamp()


@cli.command(help="Generate a report of the TRO", name="report")
@click.option(
    "--template",
    "-t",
    type=StringOrPath(_TEMPLATES),
    required=True,
    help=f"Template file or one of the following: {', '.join(_TEMPLATES.keys())}",
)
@click.option("--output", "-o", type=click.Path(), required=True, help="Output file")
@click.pass_context
def generate_report(ctx, template, output):
    declaration = ctx.parent.params.get("declaration")
    if template in _TEMPLATES:
        template = os.path.join(
            os.path.dirname(__file__), _TEMPLATES[template]["filename"]
        )
    tro = TRO(
        filepath=declaration,
    )
    tro.generate_report(template, output)


@performance.command(help="Add performance to the TRO", name="add")
@click.option(
    "--comment",
    "-m",
    type=click.STRING,
    required=False,
    help="Description of the performance",
)
@click.option(
    "--start",
    "-s",
    type=click.DateTime(),
    required=False,
    help="Start time of the performance",
)
@click.option(
    "--end",
    "-e",
    type=click.DateTime(),
    required=False,
    help="End time of the performance",
)
@click.option(
    "--caps",
    "-c",
    type=click.Choice([TRPAttribute.ISOLATION, TRPAttribute.RECORD_NETWORK]),
    required=False,
    multiple=True,
    help="Capabilities of the performance",
)
@click.option(
    "--accessed", "-a", type=click.STRING, required=False, help="Accessed Arrangement"
)
@click.option(
    "--modified", "-M", type=click.STRING, required=False, help="Modified Arrangement"
)
@click.pass_context
def performance_add(ctx, comment, start, end, caps, accessed, modified):
    ctx = ctx.parent.parent
    declaration = ctx.params.get("declaration")
    gpg_fingerprint = ctx.params.get("gpg_fingerprint")
    gpg_passphrase = ctx.params.get("gpg_passphrase")
    profile = ctx.params.get("profile")
    tro = TRO(
        filepath=declaration,
        gpg_fingerprint=gpg_fingerprint,
        gpg_passphrase=gpg_passphrase,
        profile=profile,
    )
    tro.add_performance(
        start,
        end,
        comment=comment,
        accessed_arrangement=accessed,
        modified_arrangement=modified,
        caps=caps,
    )
    tro.save()


if __name__ == "__main__":
    sys.exit(cli())  # pragma: no cover
