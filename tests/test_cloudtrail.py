import cfnlint

from hyperscale.ozone.cloudtrail import OrganizationalCloudTrail


def test_organizational_cloudtrail():
    ct = OrganizationalCloudTrail()
    t = ct.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    print(t.to_json())
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "LogArchiveBucketName" in params

    resources = d["Resources"]
    assert "OrgTrail" in resources
