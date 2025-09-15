from troposphere import awslambda
from troposphere import GetAtt
from troposphere import iam
from troposphere import logs
from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import s3
from troposphere import Sub
from troposphere import Template

from hyperscale.ozone import cfn_nag
from hyperscale.ozone.s3 import SecureS3


def _load_handler_code() -> str:
    with open("hyperscale/ozone/rvm_lambda.py") as file:
        return file.read()


class RoleVendingMachine:
    def create_template(self) -> Template:
        template = Template()
        self.add_resources(template)
        return template

    def add_resources(self, template: Template) -> None:
        pipeline_bucket_access_logs_param = template.add_parameter(
            Parameter(
                "RvmPipelineBucketAccessLogBucket",
                Type="String",
                Description="Access log bucket for the RVM pipeline bucket",
            )
        )
        template.add_parameter(
            Parameter(
                "GitHubRepo",
                Type="String",
                Description="The GitHub repo that can deploy RVM configuration, e.g. "
                "hyperscale-consulting/rvm-configuration",
            )
        )
        github_oidc_provider_arn = template.add_parameter(
            Parameter(
                "GitHubOidcProviderArn",
                Type="String",
                Description="The ARN of the OIDC provider for GitHub",
            )
        )
        rvm_main_role = template.add_resource(
            iam.Role(
                "RvmMainRole",
                Metadata=cfn_nag.suppress(
                    [
                        cfn_nag.rule(
                            id="W28",
                            reason="Static role name so it can be easily referred to "
                            "in the RVM workflow role policy",
                        )
                    ]
                ),
                RoleName="RvmMainRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                        }
                    ],
                },
                ManagedPolicyArns=[
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                ],
                Policies=[
                    iam.Policy(
                        PolicyName="RVMLambdaPolicy",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Resource": Sub(
                                        "arn:${AWS::Partition}:iam::*:role/RvmWorkflowRole"
                                    ),
                                }
                            ],
                        },
                    )
                ],
            )
        )
        log_group = template.add_resource(
            logs.LogGroup(
                "RvmLogGroup",
                DeletionPolicy="Delete",
                UpdateReplacePolicy="Delete",
                Metadata=cfn_nag.suppress(
                    [cfn_nag.rule(id="W84", reason="No sensitive data logged")]
                ),
                LogGroupName="/aws/lambda/rvm",
                RetentionInDays="7",
            )
        )
        code = _load_handler_code()
        rvm_func = template.add_resource(
            awslambda.Function(
                "RvmLambdaFunction",
                Metadata=cfn_nag.suppress(
                    [
                        cfn_nag.rule(id="W89", reason="No need for VPC access"),
                        cfn_nag.rule(
                            id="W92",
                            reason="This use case does not need to set the "
                            "ReservedConcurrentExecutions",
                        ),
                    ],
                ),
                Runtime="python3.12",
                Code=awslambda.Code(ZipFile=code.strip()),
                Handler="index.handle",
                Role=GetAtt(rvm_main_role, "Arn"),
                Timeout=900,
                MemorySize=512,
                Architectures=["arm64"],
                LoggingConfig=awslambda.LoggingConfig(
                    LogGroup=Ref(log_group),
                    LogFormat="JSON",
                    ApplicationLogLevel="INFO",
                    SystemLogLevel="INFO",
                ),
            )
        )

        pipeline_s3 = SecureS3(
            scope="RvmPipeline",
            access_logs_param=pipeline_bucket_access_logs_param,
            notification_config=s3.NotificationConfiguration(
                LambdaConfigurations=[
                    s3.LambdaConfigurations(
                        Event="s3:ObjectCreated:*",
                        Function=Ref(rvm_func),
                        Filter=s3.Filter(
                            S3Key=s3.S3Key(
                                Rules=[s3.Rules(Name="suffix", Value=".zip")]
                            )
                        ),
                    )
                ]
            ),
            policy_statements=[
                {
                    "Sid": "AllowRvmLambdaRead",
                    "Effect": "Allow",
                    "Principal": {"AWS": GetAtt(rvm_main_role, "Arn")},
                    "Action": "s3:GetObject",
                    "Resource": Sub("${RvmPipelineBucket.Arn}/rvm-configuration.zip"),
                },
            ],
        )
        pipeline_s3.add_resources(template)

        template.add_resource(
            awslambda.Permission(
                "LambdaInvokePermission",
                FunctionName=Ref(rvm_func),
                Action="lambda:InvokeFunction",
                Principal="s3.amazonaws.com",
                SourceArn=Sub("${RvmPipelineBucket.Arn}/rvm-configuration.zip"),
            )
        )
        ci_role = template.add_resource(
            iam.Role(
                "RvmCiCdRole",
                AssumeRolePolicyDocument={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Federated": Ref(github_oidc_provider_arn)},
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.github.com:aud": "sts.amazonaws.com",
                                    "token.actions.github.com:sub": Sub(
                                        "repo:${GitHubRepo}:ref:refs/heads/main"
                                    ),
                                }
                            },
                        }
                    ],
                },
                Policies=[
                    iam.Policy(
                        PolicyName="RvmCiCdPolicy",
                        PolicyDocument={
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:PutObject",
                                    ],
                                    "Resource": [
                                        Sub(
                                            "${RvmPipelineBucket.Arn}/rvm-configuration.zip"
                                        ),
                                    ],
                                },
                            ],
                        },
                    )
                ],
            )
        )

        template.add_output(
            Output(
                "RvmPipelineBucket",
                Description="RVM Pipeline Bucket",
                Value=Ref(pipeline_s3.bucket),
            )
        )
        template.add_output(
            Output(
                "RvmCiRole",
                Description="ARN of the RVM CI/CD Role",
                Value=GetAtt(ci_role, "Arn"),
            )
        )
