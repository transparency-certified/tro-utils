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


@cli.command(help="Scan a directory and add it as a composition to the TRO")
@click.argument("directory", type=click.Path(exists=True))
@click.pass_context
def scan(ctx, directory):
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
    tro.scan_directory(directory)
    tro.save()


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
