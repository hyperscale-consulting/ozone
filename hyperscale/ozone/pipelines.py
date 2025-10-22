from dataclasses import dataclass

from troposphere import codebuild
from troposphere import codepipeline
from troposphere import GetAtt
from troposphere import iam
from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import s3
from troposphere import Sub
from troposphere import Template

from hyperscale.ozone.iam import GitHubOIDCProvider
from hyperscale.ozone.s3 import SecureS3


class LandingZoneConfigurationPipeline:
    def create_template(self):
        template = Template()
        template.set_description(
            "A pipeline that maintains a landing zone using signed config files "
            "deployed from github"
        )
        self.add_resources(template)
        return template

    def add_resources(self, template: Template):
        oidc_provider = GitHubOIDCProvider()
        oidc_provider.add_resources(template)

        access_logs_bucket = SecureS3(
            "AccessLogs",
            bucket_name=Sub("${Namespace}-config-access-logs-${AWS::AccountId}"),
            is_access_logs_bucket=True,
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logging.s3.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": Sub("${AccessLogsBucket.Arn}/*"),
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": Sub("${AWS::AccountId}")},
                    },
                },
            ],
            retention_days=365,
        )
        access_logs_bucket.add_resources(template)

        pipeline = StaxPipeline(
            oidc_provider=oidc_provider.oidc_provider,
            s3_access_logs_bucket=access_logs_bucket.bucket,
        )
        pipeline.add_resources(template)


@dataclass
class StaxPipeline:
    oidc_provider: iam.OIDCProvider | Parameter | None = None
    s3_access_logs_bucket: s3.Bucket | Parameter | None = None
    admin_role_arn: iam.Role | None = None
    execution_role_name: str | None = None

    def create_template(self):
        template = Template()
        template.set_description(
            "A pipeline that deploys stack sets using stax and signed config files "
            "deployed from github"
        )
        self.add_resources(template)
        return template

    def add_resources(self, template: Template):
        template.add_parameter(
            Parameter(
                "Namespace",
                Description="The namespace for stacks deployed by this pipeline",
                Type="String",
            )
        )
        template.add_parameter(
            Parameter(
                "PublishWorkflow",
                Description="The trusted publisher workflow e.g. publish.yaml",
                Type="String",
            )
        )
        template.add_parameter(
            Parameter(
                "RepoOwner",
                Description="The owner of the trusted publishing github repo",
                Type="String",
            )
        )
        template.add_parameter(
            Parameter(
                "Repo",
                Description="The trusted publishing repo",
                Type="String",
            )
        )

        if not self.oidc_provider:
            self.oidc_provider = template.add_parameter(
                Parameter(
                    "GitHubOIDCProviderArn",
                    Type="String",
                    Description="The GitHub OIDC Provider ARN",
                )
            )

        publishing_role = template.add_resource(
            iam.Role(
                "PublishingRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Federated": Ref(self.oidc_provider)},
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": (
                                        "sts.amazonaws.com"
                                    ),
                                },
                                "StringLike": {
                                    "token.actions.githubusercontent.com:sub": Sub(
                                        "repo:${RepoOwner}/${Repo}:ref:refs/tags/v*"
                                    )
                                },
                            },
                        }
                    ],
                },
                Policies=[
                    iam.Policy(
                        PolicyName="PublishLzArchive",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Action": "s3:PutObject",
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::${SourceBucket}/*"
                                    ),
                                    "Effect": "Allow",
                                }
                            ],
                        },
                    )
                ],
            )
        )

        if not self.s3_access_logs_bucket:
            self.s3_access_logs_bucket = template.add_parameter(
                Parameter(
                    "S3AccessLogsBucket",
                    Type="String",
                    Description="The bucket for S3 access logs",
                )
            )
        source_bucket = SecureS3(
            "Source",
            bucket_name=Sub("${Namespace}-config-source-${AWS::AccountId}"),
            access_logs_bucket=Ref(self.s3_access_logs_bucket),
            retention_days=7,
        )
        source_bucket.add_resources(template)

        artifact_bucket = SecureS3(
            "Artifact",
            bucket_name=Sub("${Namespace}-config-artifact-${AWS::AccountId}"),
            access_logs_bucket=Ref(self.s3_access_logs_bucket),
            retention_days=7,
        )
        artifact_bucket.add_resources(template)

        pipeline_role = template.add_resource(
            iam.Role(
                "PipelineRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "codepipeline.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                Policies=[],
            )
        )

        source_action_role = template.add_resource(
            iam.Role(
                "SourceActionRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": GetAtt(pipeline_role, "Arn")},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                Policies=[
                    iam.Policy(
                        PolicyName="PipelinePolicy",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:ListBucket",
                                        "s3:GetObject",
                                        "s3:GetObjectVersion",
                                        "s3:GetBucketVersioning",
                                        "s3:GetBucketAcl",
                                        "s3:GetBucketLocation",
                                        "s3:GetObjectTagging",
                                        "s3:GetObjectVersionTagging",
                                    ],
                                    "Resource": [
                                        Sub(
                                            "arn:${AWS::Partition}:s3:::${SourceBucket}"
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:s3:::${SourceBucket}/*"
                                        ),
                                    ],
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:ListBucket",
                                    ],
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::${ArtifactBucket}"
                                    ),
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:PutObject",
                                    ],
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::${ArtifactBucket}/*"
                                    ),
                                },
                            ],
                        },
                    ),
                ],
            )
        )

        build_action_role = template.add_resource(
            iam.Role(
                "BuildActionRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": GetAtt(pipeline_role, "Arn")},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                Policies=[
                    iam.Policy(
                        PolicyName="BuildActionPolicy",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "codebuild:BatchGetBuilds",
                                        "codebuild:StartBuild",
                                        "codebuild:BatchGetBuildBatches",
                                        "codebuild:StartBuildBatch",
                                    ],
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:codebuild:${AWS::Region}:${AWS::AccountId}:project/${BuildProject}"
                                    ),
                                }
                            ],
                        },
                    ),
                ],
            )
        )

        codebuild_role = template.add_resource(
            iam.Role(
                "CodebuildRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "codebuild.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                Policies=[
                    iam.Policy(
                        PolicyName="CodebuildPolicy",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "ManageStackSets",
                                    "Effect": "Allow",
                                    "Action": [
                                        "cloudformation:CreateStackInstances",
                                        "cloudformation:DeleteStackInstances",
                                        "cloudformation:DeleteStack",
                                        "cloudformation:ListStackInstances",
                                        "cloudformation:DescribeStackSet",
                                        "cloudformation:DescribeStacks",
                                        "cloudformation:UpdateStackSet",
                                        "cloudformation:UpdateStack",
                                        "cloudformation:GetTemplateSummary",
                                        "cloudformation:TagResource",
                                    ],
                                    "Resource": [
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:*:${AWS::AccountId}:stackset/${Namespace}-*",
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:*:${AWS::AccountId}:stack/${Namespace}-*",
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:*:${AWS::AccountId}:stackset-target/${Namespace}-*",
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:*::type/resource/*",
                                        ),
                                    ],
                                },
                                {
                                    "Sid": "ManageStackSetsOnNonSpecificResources",
                                    "Effect": "Allow",
                                    "Action": [
                                        "cloudformation:CreateStackSet",
                                        "cloudformation:CreateStack",
                                        "cloudformation:DescribeStackSet",
                                        "cloudformation:ListStackSets",
                                        "cloudformation:ListStacks",
                                    ],
                                    "Resource": "*",
                                },
                                {
                                    "Sid": "S3Access",
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::${ArtifactBucket}/*"
                                    ),
                                },
                                {
                                    "Sid": "CreateLogs",
                                    "Effect": "Allow",
                                    "Action": [
                                        "logs:CreateLogGroup",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                    ],
                                    "Resource": [
                                        Sub(
                                            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/codebuild/*"
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/codebuild/*:*",
                                        ),
                                    ],
                                },
                                {
                                    "Sid": "PassRole",
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": "*",
                                },
                            ],
                        },
                    )
                ],
            )
        )

        build_project = template.add_resource(
            codebuild.Project(
                "BuildProject",
                Artifacts=codebuild.Artifacts(
                    Type="CODEPIPELINE",
                ),
                Environment=codebuild.Environment(
                    ComputeType="BUILD_GENERAL1_SMALL",
                    Image="ghcr.io/hyperscale-consulting/stax@sha256:cb58976dc7479dced3afc4c803f56faa6035338dfc9720354794d29b490cc401",
                    Type="LINUX_CONTAINER",
                ),
                Source=codebuild.Source(
                    Type="CODEPIPELINE",
                    BuildSpec=Sub(
                        _build_spec(self.admin_role_arn, self.execution_role_name)
                    ),
                ),
                ServiceRole=GetAtt(codebuild_role, "Arn"),
            )
        )

        template.add_resource(
            codepipeline.Pipeline(
                "Pipeline",
                ArtifactStore=codepipeline.ArtifactStore(
                    Type="S3",
                    Location=Ref(artifact_bucket.bucket),
                ),
                PipelineType="V1",
                RoleArn=GetAtt(pipeline_role, "Arn"),
                Stages=[
                    codepipeline.Stages(
                        Name="Source",
                        Actions=[
                            codepipeline.Actions(
                                Name="Source",
                                ActionTypeId=codepipeline.ActionTypeId(
                                    Category="Source",
                                    Owner="AWS",
                                    Provider="S3",
                                    Version="1",
                                ),
                                OutputArtifacts=[
                                    codepipeline.OutputArtifacts(Name="Source")
                                ],
                                Configuration={
                                    "S3Bucket": Ref(source_bucket.bucket),
                                    "S3ObjectKey": Sub("${Namespace}-archive.zip"),
                                },
                                RoleArn=GetAtt(source_action_role, "Arn"),
                            )
                        ],
                    ),
                    codepipeline.Stages(
                        Name="Build",
                        Actions=[
                            codepipeline.Actions(
                                Name="Build",
                                ActionTypeId=codepipeline.ActionTypeId(
                                    Category="Build",
                                    Owner="AWS",
                                    Provider="CodeBuild",
                                    Version="1",
                                ),
                                InputArtifacts=[
                                    codepipeline.InputArtifacts(Name="Source")
                                ],
                                Configuration={
                                    "ProjectName": Ref(build_project),
                                    "PrimarySource": "Source",
                                },
                                RoleArn=GetAtt(build_action_role, "Arn"),
                            )
                        ],
                    ),
                ],
            )
        )
        template.add_output(
            Output(
                "PublishingRole",
                Description="The role assumed by the trusted publisher",
                Value=Ref(publishing_role),
            )
        )


def _build_spec(admin_role_arn: iam.Role | None, execution_role_name: str | None):
    self_managed_args = (
        admin_role_arn
        and f"-a ${{{admin_role_arn.title}.Arn}} -e {execution_role_name}"
        or ""
    )
    return (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - ls\n"
        "      - stax deploy -n ${Namespace} "
        f"{self_managed_args} "
        "-s ${Namespace}-config.zip.sigstore.json "
        "-i https://github.com/${RepoOwner}/${Repo}/.github/workflows/"
        "${PublishWorkflow}@refs/tags/v$(cat VERSION.txt) "
        "-r https://token.actions.githubusercontent.com "
        "${Namespace}-config.zip\n"
    )
