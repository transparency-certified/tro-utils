"""Console script for tro_utils."""
import sys

import click

from .tro_utils import TRO


@click.group()
@click.option(
    "--declaration",
    type=click.Path(),
    required=False,
    help="Path to the TRO declaration file",
)
@click.option(
    "--profile", type=click.Path(), required=False, help="Path to the TRS profile file"
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
def cli(declaration, profile, gpg_fingerprint, gpg_passphrase):
    pass


@cli.command(help="Verify that TRO is signed and timestamped correctly")
@click.pass_context
def verify(ctx):
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
    tro.verify_timestamp()


@cli.group(help="Manage arrangements in the TRO")
def arrangement():
    pass


@cli.group(help="Manage compositions in the TRO")
def composition():
    pass


@composition.command(help="Get info about current composition")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
@click.pass_context
def info(ctx, verbose):
    declaration = ctx.parent.params.get("declaration")
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
    tro.add_arrangement(directory, ignore_dirs=ignore_dir, comment=comment)
    tro.save()


@arrangement.command(help="List available arrangements in the TRO")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed information")
@click.pass_context
def list(ctx, verbose):
    declaration = ctx.parent.params.get("declaration")
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
    tro.get_timestamp()


if __name__ == "__main__":
    sys.exit(cli())  # pragma: no cover
