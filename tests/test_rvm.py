import cfnlint

from hyperscale.ozone import rvm


def test_rvm():
    t = rvm.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "GitHubRepo" in params
    assert "RvmPipelineBucketAccessLogBucket" in params
    assert "GitHubOidcProviderArn" in params

    resources = d["Resources"]
    assert "RvmPipelineBucket" in resources
