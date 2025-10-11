import click

from hyperscale.ozone.cloudtrail import OrganizationalCloudTrail
from hyperscale.ozone.iam import GitHubOIDCProvider
from hyperscale.ozone.iam import GitLabOIDCProvider
from hyperscale.ozone.pipelines import LandingZoneConfigurationPipeline
from hyperscale.ozone.route53resolver import Route53ResolverQueryLoggingConfig
from hyperscale.ozone.rvm import RoleVendingMachine
from hyperscale.ozone.rvm import WorkflowRole
from hyperscale.ozone.s3 import CentralLogArchiveBuckets
from hyperscale.ozone.s3 import CentralS3AccessLogsReplicationRole
from hyperscale.ozone.s3 import LocalAccessLogsBucket
from hyperscale.ozone.s3 import OrganizationAssetsBucket


@click.group()
@click.version_option(package_name="hyperscale.ozone")
def main():
    """Ozone - higher level cloud constructs build on troposphere."""
    pass


TEMPLATES = {
    "organizational-cloudtrail": (
        OrganizationalCloudTrail(),
        "An organizational CloudTrail",
    ),
    "route53-resolver-query-logging-config": (
        Route53ResolverQueryLoggingConfig(),
        "A Route 53 Resolver Query Logging Configuration",
    ),
    "central-log-archive-buckets": (
        CentralLogArchiveBuckets(),
        "Central log archive buckets",
    ),
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
    "gitlab-oidc-provider": (GitLabOIDCProvider(), "An IAM OIDC provider for GitLab"),
    "central-s3-access-logs-replication-role": (
        CentralS3AccessLogsReplicationRole(),
        "A role for replicating s3 objects to the central s3 access logs bucket",
    ),
    "landing-zone-configuration-pipeline": (
        LandingZoneConfigurationPipeline(),
        "A pipeline for landing zone configuration",
    ),
    "organization-assets-bucket": (
        OrganizationAssetsBucket(),
        "An organization assets bucket",
    ),
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
