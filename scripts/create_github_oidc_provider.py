from hyperscale.ozone.iam import GitHubOIDCProvider

oidc = GitHubOIDCProvider()
print(oidc.create_template().to_yaml())
