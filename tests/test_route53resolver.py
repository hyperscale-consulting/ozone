import cfnlint

from hyperscale.ozone.route53resolver import Route53ResolverQueryLoggingConfig


def test_organizational_cloudtrail():
    c = Route53ResolverQueryLoggingConfig()
    t = c.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    print(t.to_json())
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "Namespace" in params
    assert "LogDestinationArn" in params

    resources = d["Resources"]
    assert "QueryLoggingConfig" in resources
