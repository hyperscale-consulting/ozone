from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import route53resolver
from troposphere import ssm
from troposphere import Sub
from troposphere import Template


class Route53ResolverQueryLoggingConfig:
    def create_template(self):
        t = Template()
        t.set_description("Route 53 Resolver Query Logging Configuration")
        self.add_resources(t)
        return t

    def add_resources(self, t: Template):
        t.add_parameter(
            Parameter(
                "Namespace",
                Type="String",
                Description=(
                    "The namespace for the SSM parameter containing the config ID"
                ),
                Default="/hyperscale/ozone",
            )
        )
        log_destination_arn_param = t.add_parameter(
            Parameter(
                "LogDestinationArn",
                Type="String",
                Description="The ARN of the destination to send query logs to",
            )
        )
        config = t.add_resource(
            route53resolver.ResolverQueryLoggingConfig(
                "QueryLoggingConfig",
                DestinationArn=Ref(log_destination_arn_param),
            )
        )
        t.add_resource(
            ssm.Parameter(
                "Route53ResolverQueryLoggingConfigId",
                Name=Sub("${Namespace}/route53resolver/query-logging-config/id"),
                Type="String",
                Value=Ref(config),
                Description=(
                    "The ID of the Route 53 Resolver Query Logging Configuration"
                ),
            )
        )
        t.add_output(Output("ResolverQueryLoggingConfigId", Value=Ref(config)))
