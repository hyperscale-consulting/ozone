from troposphere import iam
from troposphere import Output
from troposphere import Ref
from troposphere import Template


class GitHubOIDCProvider:
    def create_template(self):
        t = Template()

        provider = t.add_resource(
            iam.OIDCProvider(
                "GitHubOIDCProvider",
                Url="https://token.actions.githubusercontent.com",
                ClientIdList=["sts.amazonaws.com"],
                ThumbprintList=["1B511ABEAD59C6CE207077C0BF0E0043B1382612"],
            )
        )

        t.add_output(
            Output(
                "OIDCProviderArn",
                Description="The ARN of the OIDC provider for GitHub",
                Value=Ref(provider),
            )
        )
        return t
