from dataclasses import dataclass

from troposphere import iam
from troposphere import Output
from troposphere import Ref
from troposphere import Template


@dataclass
class OidcProvider:
    name: str
    url: str
    client_id_list: list[str]
    thumbprint_list: list[str]

    def create_template(self):
        t = Template()
        self.add_resources(t)
        t.add_output(
            Output(
                "OIDCProviderArn",
                Description="The ARN of the OIDC provider",
                Value=Ref(self.oidc_provider),
            )
        )
        return t

    def add_resources(self, template: Template):
        provider = template.add_resource(
            iam.OIDCProvider(
                self.name,
                Url=self.url,
                ClientIdList=self.client_id_list,
                ThumbprintList=self.thumbprint_list,
            )
        )

        self.oidc_provider = provider


class GitHubOIDCProvider:
    def __init__(self):
        self.delegate = OidcProvider(
            "GitHubOIDCProvider",
            url="https://token.actions.githubusercontent.com",
            client_id_list=["sts.amazonaws.com"],
            thumbprint_list=["1B511ABEAD59C6CE207077C0BF0E0043B1382612"],
        )

    def create_template(self):
        t = self.delegate.create_template()
        self.oidc_provider = self.delegate.oidc_provider
        return t

    def add_resources(self, template: Template):
        self.delegate.add_resources(template)
        self.oidc_provider = self.delegate.oidc_provider


class GitLabOIDCProvider:
    def __init__(self):
        self.delegate = OidcProvider(
            "GitLabOIDCProvider",
            url="https://gitlab.com",
            client_id_list=["https://gitlab.com"],
            thumbprint_list=["b3dd7606d2b5a8b4a13771dbecc9ee1cecafa38a"],
        )

    def create_template(self):
        t = self.delegate.create_template()
        self.oidc_provider = self.delegate.oidc_provider
        return t

    def add_resources(self, template: Template):
        self.delegate.add_resources(template)
        self.oidc_provider = self.delegate.oidc_provider
