from dataclasses import dataclass
from dataclasses import field
from typing import Any

from troposphere import AWSHelperFn
from troposphere import iam
from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import s3
from troposphere import ssm
from troposphere import Sub
from troposphere import Template

from hyperscale.ozone import cfn_nag


class OrganizationAssetsBucket:
    def create_template(self) -> Template:
        t = Template()
        t.set_description("S3 bucket for organization shared assets.")
        self.add_resources(t)
        return t

    def add_resources(self, t: Template) -> None:
        org_id_param = t.add_parameter(
            Parameter("OrgId", Type="String", Description="The AWS Organization ID")
        )
        s3_access_logs_bucket_ssm_param = t.add_parameter(
            Parameter(
                "S3AccessLogsBucketSsmParam",
                Type="AWS::SSM::Parameter::Value<String>",
                Description="The SSM parameter to fetch the S3 access logs bucket name",
            )
        )
        bucket = SecureS3(
            "OrganizationAssets",
            access_logs_bucket=Ref(s3_access_logs_bucket_ssm_param),
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                    "Resource": Sub(
                        "arn:${AWS::Partition}:s3:::${OrganizationAssetsBucket}/*"
                    ),
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": Ref(org_id_param)},
                    },
                }
            ],
            bucket_name=Sub("organization-assets-${AWS::AccountId}-${AWS::Region}"),
            retention_days=3650,
        )
        bucket.add_resources(t)


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
                Description="The full name of the central S3 access logs bucket.",
            )
        )
        t.add_parameter(
            Parameter(
                "LocalS3AccessLogsBucketPrefix",
                Type="String",
                Description="The prefix name of the local S3 access logs bucket e.g. "
                "s3-access-logs. Assumes name format of "
                "<BucketPrefix>-<AccountId>-<Region>",
            )
        )
        t.add_parameter(
            Parameter(
                "ReplicationRoleName",
                Type="String",
                Description="The name of the replication role to create",
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
                RoleName=Sub("${ReplicationRoleName}"),
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
                                        "arn:${AWS::Partition}:s3:::${LocalS3AccessLogsBucketPrefix}-${AWS::AccountId}-${AWS::Region}"
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
                                        "arn:${AWS::Partition}:s3:::${LocalS3AccessLogsBucketPrefix}-${AWS::AccountId}-${AWS::Region}/*"
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
                                        "arn:${AWS::Partition}:s3:::${CentralS3AccessLogsBucket}/*",
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
        t.add_parameter(
            Parameter(
                "LocalS3AccessLogsBucketPrefix",
                Type="String",
                Description="The prefix name of the local S3 access logs bucket e.g. "
                "s3-access-logs. Final bucket name format is "
                "<BucketPrefix>-<AccountId>-<Region>",
            )
        )
        bucket_name_ssm_param = t.add_parameter(
            Parameter(
                "LocalS3AccessLogsBucketSsmParam",
                Type="String",
                Description=(
                    "The SSM parameter to store the full S3 access logs bucket name"
                ),
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
            bucket_name=Sub(
                "${LocalS3AccessLogsBucketPrefix}-${AWS::AccountId}-${AWS::Region}"
            ),
            is_access_logs_bucket=True,
            retention_days=1,
            replication_config=replication_config,
        )
        access_logs_bucket.add_resources(t)

        t.add_resource(
            ssm.Parameter(
                "AccessLogsBucketSsmParam",
                Name=Ref(bucket_name_ssm_param),
                Type="String",
                Value=Sub(
                    "${LocalS3AccessLogsBucketPrefix}-${AWS::AccountId}-${AWS::Region}"
                ),
                Description="The S3 local access logs bucket name",
            )
        )

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
    def create_template(self) -> Template:
        t = Template()
        t.set_description("Central log archive buckets.")
        t.add_parameter(
            Parameter(
                "S3AccessLogsBucketPrefix",
                Type="String",
                Description="The prefix name of the S3 access logs bucket e.g. "
                "central-s3-access-logs. Final bucket name format is "
                "<BucketPrefix>-<AccountId>-<Region>",
            )
        )
        t.add_parameter(
            Parameter(
                "LogsBucketPrefix",
                Type="String",
                Description="The prefix name of the logs bucket e.g. "
                "central-logs. Final bucket name format is "
                "<BucketPrefix>-<AccountId>-<Region>",
            )
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
        org_id_param = t.add_parameter(
            Parameter("OrgId", Type="String", Description="The AWS Organization ID")
        )
        t.add_parameter(
            Parameter("AuditAccount", Type="String", Description="The audit account ID")
        )
        t.add_parameter(
            Parameter(
                "ReplicationRoleName",
                Type="String",
                Description="The name of the role that allows replication to the s3 "
                "access logs bucket",
            )
        )

        access_logs_bucket = SecureS3(
            "AccessLogs",
            bucket_name=Sub(
                "${S3AccessLogsBucketPrefix}-${AWS::AccountId}-${AWS::Region}"
            ),
            policy_statements=[
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"],
                    "Resource": Sub("arn:${AWS::Partition}:s3:::${AccessLogsBucket}/*"),
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": Ref(org_id_param)},
                        "ArnLike": {
                            "aws:PrincipalArn": Sub(
                                "arn:${AWS::Partition}:iam::*:role/${ReplicationRoleName}"
                            )
                        },
                    },
                }
            ],
            retention_days=Ref(retention_days_for_access_logs),
            is_access_logs_bucket=True,
        )
        access_logs_bucket.add_resources(t)

        logs_bucket = SecureS3(
            "Logs",
            policy_statements=[
                {
                    "Sid": "ELBLogDeliveryWrite",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "logdelivery.elasticloadbalancing.amazonaws.com"
                    },
                    "Action": "s3:PutObject",
                    "Resource": Sub(
                        "arn:${AWS::Partition}:s3:::${LogsBucket}/AWSLogs/*"
                    ),
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceOrgId": Ref(org_id_param),
                        },
                        "ArnLike": {
                            "aws:SourceArn": Sub(
                                "arn:${AWS::Partition}:elasticloadbalancing:${AWS::Region}:*:loadbalancer/*"
                            )
                        },
                    },
                },
                {
                    "Sid": "AWSLogDeliveryWrite",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "delivery.logs.amazonaws.com",
                            "config.amazonaws.com",
                            "cloudtrail.amazonaws.com",
                        ]
                    },
                    "Action": "s3:PutObject",
                    "Resource": Sub("arn:${AWS::Partition}:s3:::${LogsBucket}/*"),
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceOrgId": Ref(org_id_param),
                        },
                    },
                },
                {
                    "Sid": "AclCheck",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "delivery.logs.amazonaws.com",
                            "config.amazonaws.com",
                            "cloudtrail.amazonaws.com",
                        ]
                    },
                    "Action": "s3:GetBucketAcl",
                    "Resource": Sub("arn:${AWS::Partition}:s3:::${LogsBucket}"),
                },
                {
                    "Sid": "BucketExistenceCheck",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "delivery.logs.amazonaws.com",
                            "config.amazonaws.com",
                            "cloudtrail.amazonaws.com",
                        ]
                    },
                    "Action": "s3:ListBucket",
                    "Resource": Sub("arn:${AWS::Partition}:s3:::${LogsBucket}"),
                },
                {
                    "Sid": "AuditAccountRead",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": Sub("arn:${AWS::Partition}:iam::${AuditAccount}:root"),
                    },
                    "Action": ["s3:ListBucket", "s3:GetObject"],
                    "Resource": [
                        Sub("arn:${AWS::Partition}:s3:::${LogsBucket}"),
                        Sub("arn:${AWS::Partition}:s3:::${LogsBucket}/*"),
                    ],
                },
            ],
            bucket_name=Sub("${LogsBucketPrefix}-${AWS::AccountId}-${AWS::Region}"),
            retention_days=Ref(retention_days_for_logs),
            access_logs_bucket=Ref(access_logs_bucket.bucket),
        )
        logs_bucket.add_resources(t)

        return t
