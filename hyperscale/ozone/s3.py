from dataclasses import dataclass
from dataclasses import field
from typing import Any

from troposphere import Parameter
from troposphere import Ref
from troposphere import s3
from troposphere import Sub
from troposphere import Template


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
