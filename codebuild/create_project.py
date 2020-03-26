#!/usr/bin/env python3
# -*- coding: utf-8 -*-
copywrite = """# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
"""

import argparse
import boto3
import configparser
import logging

from awacs.aws import Action, Allow, Statement, Principal, PolicyDocument
from awacs.sts import AssumeRole
from botocore import exceptions
from random import randrange
from troposphere import GetAtt, Template, Ref, Output
from troposphere.events import Rule, Target
from troposphere.iam import Role, Policy
from troposphere.codebuild import Artifacts, Environment, Source, Project

logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def build_cw_event(template=Template, project_name=None, role=None):
    """ Create a CloudWatch Event to run a CodeBuild Project. """
    # Run either at 12 or 13:00 UTC, 04/05:00 PST
    hour = randrange(12, 14)
    project_target = Target(
        f"{project_name}Target",
        Arn=GetAtt(project_name, "Arn"),
        RoleArn=GetAtt(role, "Arn"),
        Id=f"{project_name}CWid"
    )
    Rule(f"{project_name}Rule",
         template=template,
         Name=f"{project_name}Evernt",
         Description="scheduled run Build with CloudFormation",
         Targets=[project_target],
         State='ENABLED',
         # Run at the top of a random hour.
         ScheduleExpression=f"cron(0 {hour} * * ? *)",
         DependsOn=project_name
         )


def build_cw_cb_role(template=None, role_name="s2nEventsInvokeCodeBuildRole"):
    """
    Create a role for CloudWatch events to trigger scheduled CodeBuild jobs.
    """
    role_id = template.add_resource(
        Role(
            role_name,
            Path='/',
            AssumeRolePolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[Action("sts", "AssumeRole"),
                                ],
                        Principal=Principal("Service", ["events.amazonaws.com"])
                    )
                ]
            ),
            Policies=[Policy(
                PolicyName=f"EventsInvokeCBRole",
                PolicyDocument=PolicyDocument(
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Action=[Action("codebuild", "StartBuild")],
                            Resource=[
                                "arn:aws:codebuild:us-west-2:024603541914:project/*",
                            ]
                        )
                    ]
                )
            )
            ]
        )
    )
    return role_id


def build_github_role(template=None, role_name="s2nCodeBuildGithubRole"):
    """
    Create a role for GitHub actions to use for launching CodeBuild jobs.
    This is not attached to any other resource created in this file.
    """
    template.add_resource(
        Role(
            role_name,
            Path='/',
            AssumeRolePolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[Action("logs", "CreateLogGroup"),
                                Action("logs", "CreateLogStream"),
                                Action("logs", "PutLogEvents")],
                        Resource=[
                            "arn:aws:logs:us-west-2:024603541914:log-group:/aws/codebuild/s2nGithubCodebuild",
                            "arn:aws:logs:us-west-2:024603541914:log-group:/aws/codebuild/s2nGithubCodebuild:*"
                        ]
                    )
                ]
            )
        )
    )


def build_artifacts(identifier: str, s3_bucketname: str) -> Artifacts:
    """ CodeBuild Artifact and Secondary Artifact creation. """
    artifact = Artifacts(
        Name=f"{identifier}Artifact",
        ArtifactIdentifier=identifier,
        EncryptionDisabled=True,
        Location=s3_bucketname,
        NamespaceType='None',
        OverrideArtifactName=False,
        Packaging='Zip',
        Type='S3')
    return artifact


def build_project(template=Template(), section=None, project_name=None, raw_env=None,
                  service_role: str = None) -> Template:
    """ Assemble all the requirements for a Troposphere CodeBuild Project. """
    template.set_version('2010-09-09')
    secondary_artifacts = list()

    # Artifact object creation
    if 'artifact_s3_bucket' in config[section]:
        artifacts = build_artifacts(project_name,
                                    config.get(section, 'artifact_s3_bucket'))
        if 'artifact_secondary_identifiers' in config[section]:
            # There can be N number of secondary artifacts
            for arti in config.get(section, 'artifact_secondary_identifiers').split(','):
                secondary_artifacts.append(build_artifacts(arti, config.get(section, 'artifact_s3_bucket')))

    else:
        # One blank Artifact object required.
        artifacts = Artifacts(Type='NO_ARTIFACTS')
    env_list = list()

    # Convert the env: line in the config to a list.
    try:
        logging.debug(f'raw_env is {raw_env}')
        env = raw_env.split(' ')
    except AttributeError:
        env = config.get(section, 'env').split(' ')
        logging.debug(f'Section is {section}')

    # Split the env key/value pairs into dict.
    for i in env:
        k, v = i.split("=")
        env_list.append({"Name": k, "Value": v})

    environment = Environment(
        ComputeType=config.get(section, 'compute_type'),
        Image=str(config.get(section, 'image')),
        Type=str(config.get(section, 'env_type')),
        PrivilegedMode=True,
        EnvironmentVariables=env_list,
    )

    source = Source(
        Location=config.get(section, 'source_location'),
        Type=config.get(section, 'source_type'),
        GitCloneDepth=config.get(section, 'source_clonedepth'),
        BuildSpec=config.get(section, 'buildspec'),
        ReportBuildStatus=True
    )

    # Artifact is required; SecondaryArtifact is optional.
    if secondary_artifacts:
        project = Project(
            project_name,
            Artifacts=artifacts,
            SecondaryArtifacts=secondary_artifacts,
            Environment=environment,
            Name=project_name,
            TimeoutInMinutes=config.get(section, 'timeout_in_min'),
            ServiceRole=Ref(service_role),
            Source=source,
            SourceVersion=config.get(section, 'source_version'),
            BadgeEnabled=True,
            DependsOn=service_role,
        )
    else:
        project = Project(
            project_name,
            Artifacts=artifacts,
            Environment=environment,
            Name=project_name,
            TimeoutInMinutes=config.get(section, 'timeout_in_min'),
            ServiceRole=Ref(service_role),
            Source=source,
            SourceVersion=config.get(section, 'source_version'),
            BadgeEnabled=True,
            DependsOn=service_role,
        )
    template.add_resource(project)
    template.add_output([Output(f"CodeBuildProject{project_name}", Value=Ref(project))])


def build_codebuild_role(template=Template(), project_name: str = None, **kwargs) -> Ref:
    """ Build a role with a CodeBuild managed policy. """
    assert project_name
    project_name += 'Role'

    # Create a policy to Allow CodeBuild to write to s3 for Artifact storage/retrieval.
    # This should be an AWS Managed Policy, but here we are.
    policies = [Policy(
        PolicyName=f"CodeBuildArtifactPolicy",
        PolicyDocument=PolicyDocument(
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[Action("s3", "PutObject"),
                            Action("s3","GetObject"),
                            Action("s3","GetObjectVersion"),
                            Action("s3","GetBucketAcl"),
                            Action("s3","GetBucketLocation")],
                    Resource=[
                        "arn:aws:s3:::s2n-build-artifacts/*",
                    ]
                )
            ]
        )
    )]

    # NOTE: By default CodeBuild manages the policies for this role.  If you delete a CFN stack and try to recreate the
    # project or make changes to it when the Codebuild managed Policy still exists, you'll see an error in the UI:
    # `The policy is attached to 0 entities but it must be attached to a single role`. (CFN fails with fail to update)
    # Orphaned policies created by CodeBuild will have CodeBuildBasePolicy prepended to them; search for policies with
    # this name and no role and delete to clear the error.
    role_id = template.add_resource(
        Role(
            project_name,
            Path='/',
            Description='Policy created by CloudFormation.',
            Policies=policies,
            AssumeRolePolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[AssumeRole],
                        Principal=Principal("Service", ["codebuild.amazonaws.com"])
                    )
                ]
            )
        )
    )

    template.add_output([Output(project_name, Value=Ref(role_id))])
    return Ref(role_id)


def validate_cfn(boto_client: boto3.client, cfn_template: str):
    """ Use boto validate_template. """
    try:
        response = boto_client.validate_template(TemplateBody=cfn_template)
        logging.debug(f"CloudFormation Template validation response: {response}")
        logging.info('CloudFormation template validation complete.')
    except exceptions.ClientError as e:
        raise SystemExit(f"Failed: {e}")


def main(**kwargs):
    """ Create the CFN template and either write to screen or update/create boto3. """
    codebuild = Template()
    codebuild.set_version('2010-09-09')
    # Create a single CloudWatch Event role to allow codebuild:startBuild
    cw_event_role = build_cw_cb_role(codebuild)
    temp_yaml_filename = args.output_dir + "/s2n_codebuild_projects.yml"

    build_github_role(codebuild)
    for job in config.sections():
        if 'CodeBuild:' in job:
            job_title = job.split(':')[1]
            service_role = build_codebuild_role(template=codebuild, project_name=job_title).to_dict()
            # Pull the env out of the section, and use the snippet for the other values.
            if 'snippet' in config[job]:
                build_project(template=codebuild, project_name=job_title, section=config.get(job, 'snippet'),
                              service_role=service_role['Ref'], raw_env=config.get(job, 'env'))
            else:
                build_project(template=codebuild, project_name=job_title, section=job, service_role=service_role['Ref'])
            build_cw_event(template=codebuild, project_name=job_title, role=cw_event_role)

    with(open(temp_yaml_filename, 'w')) as fh:
        fh.write(codebuild.to_yaml())
    if args.noop:
        logging.info(f"Wrote cfn yaml file to {temp_yaml_filename}")
    else:
        # Fire up the boto
        client = boto3.client('cloudformation', region_name=config.get('Global', 'aws_region'))
        validate_cfn(client, codebuild.to_yaml())
        if args.dry_run:
            logging.info('Respecting dry-run flag.  Done')
        else:
            logging.info('Updating CloudFormation Stack')


if __name__ == '__main__':
    # Parse  options
    parser = argparse.ArgumentParser(description='Creates AWS CodeBuild Project CloudFormation files ' +
                                                 'based on a simple config')
    parser.add_argument('--config', type=str, default="codebuild.config", help='The config filename to create the '
                                                                               'CodeBuild projects')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true', help='Validate CloudFormation yaml.')
    parser.add_argument('--noop', dest='noop', action='store_true',
                        help='Create a local CFN yaml- but do no validation.')
    parser.add_argument('--output-dir', dest='output_dir', default='cfn', help="Directory to write CFN files")
    args = parser.parse_args()

    config = configparser.RawConfigParser()
    logging.debug(f'Try to load config file {args.config}')
    config.read(args.config)
    assert config.get('CFNRole', 'account_number')
    main(args=args, config=config)
