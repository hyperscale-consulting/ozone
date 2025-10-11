from troposphere import Output
from troposphere import Parameter
from troposphere import Ref
from troposphere import route53resolver
from troposphere import Template


class Route53ResolverQueryLoggingConfig:
    def create_template(self):
        t = Template()
        t.set_description("Route 53 Resolver Query Logging Configuration")
        self.add_resources(t)
        return t

    def add_resources(self, t: Template):
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
        t.add_output(Output("ResolverQueryLoggingConfigId", Value=Ref(config)))
