import cfnlint

from hyperscale.ozone.iam import GitHubOIDCProvider


def test_local_access_logs_bucket():
    oidc = GitHubOIDCProvider()
    t = oidc.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
    d = t.to_dict()

    resources = d["Resources"]
    assert "GitHubOIDCProvider" in resources

    assert "OIDCProviderArn" in d["Outputs"]
