from troposphere import cloudtrail
from troposphere import Parameter
from troposphere import Ref
from troposphere import Template


class OrganizationalCloudTrail:
    def create_template(self):
        t = Template()
        t.set_description("Organizational CloudTrail Configuration")
        self.add_resources(t)
        return t

    def add_resources(self, t: Template):
        log_archive_bucket_name_param = t.add_parameter(
            Parameter(
                "LogArchiveBucketName",
                Type="String",
                Description="The S3 bucket to store CloudTrail logs",
            )
        )
        t.add_resource(
            cloudtrail.Trail(
                "OrgTrail",
                IsOrganizationTrail=True,
                S3BucketName=Ref(log_archive_bucket_name_param),
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                IncludeGlobalServiceEvents=True,
                IsLogging=True,
            )
        )
