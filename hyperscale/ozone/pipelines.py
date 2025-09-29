from troposphere import codebuild
from troposphere import codepipeline
from troposphere import GetAtt
from troposphere import iam
from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import Sub
from troposphere import Template

from hyperscale.ozone.iam import GitHubOIDCProvider
from hyperscale.ozone.s3 import SecureS3


class LandingZoneConfigurationPipeline:
    def create_template(self):
        template = Template()
        template.set_description("A landing zone configuration pipeline")
        self.add_resources(template)
        return template

    def add_resources(self, template: Template):
        template.add_parameter(
            Parameter(
                "LandingZoneName",
                Description="The name of the landing zone",
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

        oidc_provider = GitHubOIDCProvider()
        oidc_provider.add_resources(template)

        publishing_role = template.add_resource(
            iam.Role(
                "PublishingRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": Ref(oidc_provider.oidc_provider)
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
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

        access_logs_bucket = SecureS3(
            "AccessLogs",
            bucket_name=Sub("${LandingZoneName}-config-access-logs-${AWS::AccountId}"),
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

        source_bucket = SecureS3(
            "Source",
            bucket_name=Sub("${LandingZoneName}-config-source-${AWS::AccountId}"),
            access_logs_bucket=Ref(access_logs_bucket.bucket),
            retention_days=7,
        )
        source_bucket.add_resources(template)

        artifact_bucket = SecureS3(
            "Artifact",
            bucket_name=Sub("${LandingZoneName}-config-artifact-${AWS::AccountId}"),
            access_logs_bucket=Ref(access_logs_bucket.bucket),
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
                                        "cloudformation:UpdateStackSet",
                                        "cloudformation:DescribeStackSet",
                                        "cloudformation:GetTemplateSummary",
                                    ],
                                    "Resource": [
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stackset/${LandingZoneName}-*",
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:*:${AWS::AccountId}:stackset-target/${LandingZoneName}-*",
                                        ),
                                        Sub(
                                            "arn:${AWS::Partition}:cloudformation:${AWS::Region}::type/resource/*",
                                        ),
                                    ],
                                },
                                {
                                    "Sid": "CreateStackSet",
                                    "Effect": "Allow",
                                    "Action": [
                                        "cloudformation:CreateStackSet",
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
                    Image="ghcr.io/hyperscale-consulting/stax@sha256:7fedb78139e2d5a246882b52fae37447fa82efd4e8be5c79d39a7f85918b71d3",
                    Type="LINUX_CONTAINER",
                ),
                Source=codebuild.Source(
                    Type="CODEPIPELINE",
                    BuildSpec=Sub(_build_spec()),
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
                                    "S3ObjectKey": "lz-archive.zip",
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


def _build_spec():
    return """
version: 0.2
phases:
  build:
    commands:
      - ls
      - stax deploy -p ${LandingZoneName} -s lz-config.zip.sigstore.json -i https://github.com/${RepoOwner}/${Repo}/.github/workflows/${PublishWorkflow}@refs/tags/v$(cat VERSION.txt) -r https://token.actions.githubusercontent.com lz-config.zip
"""
