from dataclasses import dataclass
from dataclasses import field
from typing import Any

from troposphere import AWSHelperFn
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
    access_logs_bucket: Ref | None = None
    policy_statements: list[dict] | None = None
    notification_config: s3.NotificationConfiguration | None = None
    bucket_name: str | Sub | None = None
    is_access_logs_bucket: bool = False
    retention_days: int | AWSHelperFn = 30
    replication_config: s3.ReplicationConfiguration | None = None
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
            LifecycleConfiguration=s3.LifecycleConfiguration(
                Rules=[
                    s3.LifecycleRule(
                        ExpirationInDays=self.retention_days,
                        NoncurrentVersionExpiration=s3.NoncurrentVersionExpiration(
                            NoncurrentDays=self.retention_days
                        ),
                        Status="Enabled",
                    )
                ]
            ),
            ObjectLockEnabled=True,
            ObjectLockConfiguration=s3.ObjectLockConfiguration(
                ObjectLockEnabled="Enabled",
                Rule=s3.ObjectLockRule(
                    DefaultRetention=s3.DefaultRetention(
                        Mode="GOVERNANCE",
                        Days=self.retention_days,
                    )
                ),
            ),
        )
        if not self.is_access_logs_bucket:
            if self.access_logs_bucket is None:
                raise ValueError(
                    "access_logs_bucket must be provided unless is_access_logs_bucket "
                    "is True"
                )
            bucket_args["LoggingConfiguration"] = s3.LoggingConfiguration(
                DestinationBucketName=self.access_logs_bucket
            )
        else:
            bucket_args["Metadata"] = cfn_nag.suppress(
                [cfn_nag.rule("W35", "This is the access logs bucket")]
            )

        if self.bucket_name:
            bucket_args["BucketName"] = self.bucket_name

        if self.notification_config:
            bucket_args["NotificationConfiguration"] = self.notification_config

        if self.replication_config:
            bucket_args["ReplicationConfiguration"] = self.replication_config

        self.bucket = template.add_resource(
            s3.Bucket(f"{self.scope}Bucket", **bucket_args)
        )
        statements = [
            {
                "Sid": "EnforceSecureTransport",
                "Effect": "Deny",
                "Action": "s3:*",
                "Principal": "*",
                "Resource": [
                    Sub(f"${{{self.scope}Bucket.Arn}}"),
                    Sub(f"${{{self.scope}Bucket.Arn}}/*"),
                ],
                "Condition": {"Bool": {"aws:SecureTransport": False}},
            },
        ] + policy_statements

        if self.is_access_logs_bucket:
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logging.s3.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": Sub(f"${{{self.scope}Bucket.Arn}}/*"),
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": Sub("${AWS::AccountId}")},
                    },
                },
            )
        template.add_resource(
            s3.BucketPolicy(
                f"{self.scope}BucketPolicy",
                Bucket=Ref(self.bucket),
                PolicyDocument={"Version": "2012-10-17", "Statement": statements},
            )
        )


class CentralS3AccessLogsReplicationRole:
    """
    Creates the replication roles required to replicate s3 access logs from
    account-local buckets to a central log archive bucket.
    """

    def create_template(self) -> Template:
        t = Template()
        t.set_description(
            "IAM role for replicating account-local s3 access logs to a central log "
            "archive bucket"
        )
        t.add_parameter(
            Parameter(
                "CentralS3AccessLogsBucket",
                Type="String",
                Description="The name of the central S3 access logs bucket.",
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

        return t


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
        t.add_parameter(
            Parameter(
                "ReplicationRoleName",
                Type="String",
                Description="The name of the role that allows replication to the "
                "central log archive bucket",
            )
        )

        replication_config = s3.ReplicationConfiguration(
            Role=Sub(
                "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${ReplicationRoleName}"
            ),
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
        )
        access_logs_bucket = SecureS3(
            "AccessLogs",
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
            bucket_name=Sub("s3-access-logs-${AWS::AccountId}-${AWS::Region}"),
            is_access_logs_bucket=True,
            retention_days=1,
            replication_config=replication_config,
        )
        access_logs_bucket.add_resources(t)

        t.add_output(
            Output(
                "S3AccessLogsBucket",
                Description="The S3 access logs bucket",
                Value=Ref(access_logs_bucket.bucket),
            )
        )

        return t


@dataclass
class CentralLogArchiveBuckets:
    account_ids: list[str]

    def create_template(self) -> Template:
        t = Template()
        t.set_description(
            "Central log archive buckets that can be used across an organization."
        )
        retention_days_for_access_logs = t.add_parameter(
            Parameter(
                "RetentionDaysForAccessLogs",
                Type="String",
                Description="The number of days the access logs should be retained for",
                Default="3650",
            )
        )
        retention_days_for_logs = t.add_parameter(
            Parameter(
                "RetentionDaysForLogs",
                Type="String",
                Description="The number of days the logs should be retained for",
                Default="3650",
            )
        )

        replication_principals = [
            Sub(
                f"arn:${{AWS::Partition}}:iam::{aid}:role/CentralS3AccessLogsReplicationRole"
            )
            for aid in self.account_ids
        ]
        access_logs_bucket = SecureS3(
            "AccessLogs",
            bucket_name=Sub("central-s3-access-logs-${AWS::AccountId}-${AWS::Region}"),
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": replication_principals},
                    "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"],
                    "Resource": Sub("arn:${AWS::Partition}:s3:::${AccessLogsBucket}/*"),
                }
            ],
            retention_days=Ref(retention_days_for_access_logs),
            is_access_logs_bucket=True,
        )
        access_logs_bucket.add_resources(t)

        statements = []
        for account_id in self.account_ids:
            statements.append(
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "logdelivery.elasticloadbalancing.amazonaws.com"
                    },
                    "Action": "s3:PutObject",
                    "Resource": Sub(
                        f"arn:${{AWS::Partition}}:s3:::${{LogsBucket}}/AWSLogs/{account_id}/*"
                    ),
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": Sub(
                                f"arn:${{AWS::Partition}}:elasticloadbalancing:${{AWS::Region}}:{account_id}:loadbalancer/*"
                            )
                        }
                    },
                }
            )
            statements.append(
                {
                    "Sid": "AWSLogDeliveryWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": Sub(
                        f"arn:${{AWS::Partition}}:s3:::${{LogsBucket}}/AWSLogs/{account_id}/*"
                    ),
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id,
                            "s3:x-amz-acl": "bucket-owner-full-control",
                        },
                        "ArnLike": {
                            "aws:SourceArn": Sub(
                                f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:{account_id}:*"
                            )
                        },
                    },
                }
            )
            statements.append(
                {
                    "Sid": "AWSLogDeliveryAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": Sub("arn:${AWS::Partition}:s3:::${LogsBucket}"),
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id,
                        },
                        "ArnLike": {
                            "aws:SourceArn": Sub(
                                f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:{account_id}:*"
                            )
                        },
                    },
                }
            )

        logs_bucket = SecureS3(
            "Logs",
            policy_statements=statements,
            bucket_name=Sub("central-logs-${AWS::AccountId}-${AWS::Region}"),
            retention_days=Ref(retention_days_for_logs),
            access_logs_bucket=Ref(access_logs_bucket.bucket),
        )
        logs_bucket.add_resources(t)

        return t
