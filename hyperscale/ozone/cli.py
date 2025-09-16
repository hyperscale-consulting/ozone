import click

from hyperscale.ozone.iam import GitHubOIDCProvider
from hyperscale.ozone.rvm import RoleVendingMachine
from hyperscale.ozone.rvm import WorkflowRole
from hyperscale.ozone.s3 import LocalAccessLogsBucket


@click.group()
@click.version_option(package_name="hyperscale.ozone")
def main():
    """Ozone - higher level cloud constructs build on troposphere."""
    pass


TEMPLATES = {
    "role-vending-machine": (RoleVendingMachine(), "A Role Vending Machine"),
    "rvm-workflow-role": (
        WorkflowRole(),
        "The workflow role for a Role Vending Machine",
    ),
    "local-access-logs-bucket": (
        LocalAccessLogsBucket(),
        "An account-local s3 access logs bucket that replicates logs to a central "
        "account",
    ),
    "github-oidc-provider": (GitHubOIDCProvider(), "An IAM OIDC provider for GitHub"),
}


@main.command()
@click.argument("template", type=click.Choice(TEMPLATES.keys()), required=True)
def create_template(template):
    """Generate the specified CloudFormation template"""
    if template not in TEMPLATES:
        raise click.ClickException(f"Unknown template: {template}")
    factory, _ = TEMPLATES[template]
    click.echo(factory.create_template().to_yaml())


@main.command()
def list_templates():
    """List all available templates"""
    for k, v in TEMPLATES.items():
        click.echo(f"{k}: {v[1]}")
