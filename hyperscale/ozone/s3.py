from dataclasses import dataclass
from dataclasses import field
from typing import Any

from troposphere import GetAtt
from troposphere import iam
from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import s3
from troposphere import Sub
from troposphere import Template

from hyperscale.ozone import cfn_nag


@dataclass
class SecureS3:
    """
    A composite S3 resource that includes access logging, versioning, server side
    encryption and secure transport by default.
    """

    scope: str
    access_logs_param: Parameter
    policy_statements: list[dict] | None = None
    notification_config: s3.NotificationConfiguration | None = None
    bucket: s3.Bucket | None = field(init=False, default=None)

    def add_resources(self, template: Template) -> None:
        policy_statements = self.policy_statements or []
        bucket_args: dict[str, Any] = dict(
            VersioningConfiguration=s3.VersioningConfiguration(Status="Enabled"),
            PublicAccessBlockConfiguration=s3.PublicAccessBlockConfiguration(
                BlockPublicAcls=True,
                BlockPublicPolicy=True,
                IgnorePublicAcls=True,
                RestrictPublicBuckets=True,
            ),
            BucketEncryption=s3.BucketEncryption(
                ServerSideEncryptionConfiguration=[
                    s3.ServerSideEncryptionRule(
                        ServerSideEncryptionByDefault=s3.ServerSideEncryptionByDefault(
                            SSEAlgorithm="AES256"
                        )
                    )
                ]
            ),
            LoggingConfiguration=s3.LoggingConfiguration(
                DestinationBucketName=Ref(self.access_logs_param)
            ),
        )
        if self.notification_config:
            bucket_args["NotificationConfiguration"] = self.notification_config

        self.bucket = template.add_resource(
            s3.Bucket(f"{self.scope}Bucket", **bucket_args)
        )
        statements = [
            {
                "Sid": "EnforceSecureTransport",
                "Effect": "Deny",
                "Action": "s3:*",
                "Principal": "*",
                "Resource": Sub(f"${{{self.scope}Bucket.Arn}}/*"),
                "Condition": {"Bool": {"aws:SecureTransport": False}},
            },
        ] + policy_statements
        template.add_resource(
            s3.BucketPolicy(
                f"{self.scope}BucketPolicy",
                Bucket=Ref(self.bucket),
                PolicyDocument={"Version": "2012-10-17", "Statement": statements},
            )
        )


class LocalAccessLogsBucket:
    """
    Creates an account local access logs bucket that replicates access logs to a
    central log bucket in a log archive account.
    """

    def create_template(self) -> Template:
        t = Template()
        t.set_description(
            "S3 access log bucket set up to replicate to a central log bucket in a "
            "log archive "
        )
        t.add_parameter(
            Parameter(
                "CentralS3AccessLogsBucket",
                Type="String",
                Description="The name of the central S3 access logs bucket.",
            )
        )
        log_archive_account_param = t.add_parameter(
            Parameter(
                "LogArchiveAccount",
                Type="String",
                Description="The ID of the Log Archive account.",
            )
        )

        t.add_resource(
            iam.Role(
                "ReplicationRole",
                Metadata=cfn_nag.suppress(
                    [
                        cfn_nag.rule(
                            "W28",
                            "Static name needed to grant permissions to replicate to "
                            "central bucket",
                        )
                    ]
                ),
                RoleName="CentralS3AccessLogsReplicationRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                Policies=[
                    iam.Policy(
                        PolicyName="AllowReplication",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:GetReplicationConfiguration",
                                        "s3:ListBucket",
                                    ],
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::s3-access-logs-${AWS::AccountId}-${AWS::Region}"
                                    ),
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:GetObjectVersionForReplication",
                                        "s3:GetObjectVersionAcl",
                                        "s3:GetObjectVersionTagging",
                                    ],
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::s3-access-logs-${AWS::AccountId}-${AWS::Region}/*"
                                    ),
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:ReplicateObject",
                                        "s3:ReplicateDelete",
                                        "s3:ReplicateTags",
                                    ],
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:s3:::${CentralS3AccessLogsBucket}/*"
                                    ),
                                },
                            ],
                        },
                    )
                ],
            )
        )

        t.add_resource(
            s3.Bucket(
                "AccessLogsBucket",
                Metadata=cfn_nag.suppress(
                    [cfn_nag.rule("W35", "This is the access logs bucket")]
                ),
                BucketName=Sub("s3-access-logs-${AWS::AccountId}-${AWS::Region}"),
                VersioningConfiguration=s3.VersioningConfiguration(Status="Enabled"),
                PublicAccessBlockConfiguration=s3.PublicAccessBlockConfiguration(
                    BlockPublicAcls=True,
                    BlockPublicPolicy=True,
                    IgnorePublicAcls=True,
                    RestrictPublicBuckets=True,
                ),
                BucketEncryption=s3.BucketEncryption(
                    ServerSideEncryptionConfiguration=[
                        s3.ServerSideEncryptionRule(
                            ServerSideEncryptionByDefault=s3.ServerSideEncryptionByDefault(
                                SSEAlgorithm="AES256"
                            )
                        )
                    ]
                ),
                OwnershipControls=s3.OwnershipControls(
                    Rules=[
                        s3.OwnershipControlsRule(ObjectOwnership="BucketOwnerEnforced")
                    ]
                ),
                ObjectLockEnabled=True,
                ReplicationConfiguration=s3.ReplicationConfiguration(
                    Role=GetAtt("ReplicationRole", "Arn"),
                    Rules=[
                        s3.ReplicationConfigurationRules(
                            Destination=s3.ReplicationConfigurationRulesDestination(
                                Account=Ref(log_archive_account_param),
                                Bucket=Sub(
                                    "arn:${AWS::Partition}:s3:::${CentralS3AccessLogsBucket}"
                                ),
                            ),
                            Status="Enabled",
                        )
                    ],
                ),
                LifecycleConfiguration=s3.LifecycleConfiguration(
                    Rules=[
                        s3.LifecycleRule(
                            ExpirationInDays=1,
                            NoncurrentVersionExpiration=s3.NoncurrentVersionExpiration(
                                NoncurrentDays=1
                            ),
                            Status="Enabled",
                        )
                    ]
                ),
            )
        )

        t.add_resource(
            s3.BucketPolicy(
                "AccessLogsBucketPolicy",
                Bucket=Ref("AccessLogsBucket"),
                PolicyDocument={
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [
                                Sub("arn:${AWS::Partition}:s3:::${AccessLogsBucket"),
                                Sub("arn:${AWS::Partition}:s3:::${AccessLogsBucket/*"),
                            ],
                            "Condition": {"Bool": {"aws:SecureTransport": False}},
                        },
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "logging.s3.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": Sub(
                                "arn:${AWS::Partition}:s3:::${AccessLogsBucket/*"
                            ),
                            "Condition": {
                                "StringEquals": {
                                    "aws:SourceAccount": Sub("${AWS::AccountId}")
                                },
                            },
                        },
                    ]
                },
            ),
        )

        t.add_output(
            Output(
                "S3AccessLogsBucket",
                Description="The S3 access logs bucket",
                Value=Ref("AccessLogsBucket"),
            )
        )

        return t
