import cfnlint

from hyperscale.ozone.s3 import CentralLogArchiveBuckets
from hyperscale.ozone.s3 import CentralS3AccessLogsReplicationRole
from hyperscale.ozone.s3 import LocalAccessLogsBucket
from hyperscale.ozone.s3 import OrganizationAssetsBucket


def test_local_access_logs_bucket():
    lalb = LocalAccessLogsBucket()
    t = lalb.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "CentralS3AccessLogsBucket" in params
    assert "LogArchiveAccount" in params
    assert "ReplicationRoleName" in params

    resources = d["Resources"]
    assert "AccessLogsBucket" in resources


def test_central_log_archive_buckets():
    buckets = CentralLogArchiveBuckets()
    t = buckets.create_template()

    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "RetentionDaysForLogs" in params
    assert "RetentionDaysForAccessLogs" in params

    resources = d["Resources"]
    assert "AccessLogsBucket" in resources
    assert "LogsBucket" in resources


def test_central_s3_access_logs_replication_role():
    role = CentralS3AccessLogsReplicationRole()
    t = role.create_template()

    errors = cfnlint.lint(t.to_json())
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "CentralS3AccessLogsBucket" in params
    resources = d["Resources"]
    assert "ReplicationRole" in resources


def test_organization_assets_bucket():
    bucket = OrganizationAssetsBucket()
    t = bucket.create_template()
    errors = cfnlint.lint(t.to_json())
    assert not errors
