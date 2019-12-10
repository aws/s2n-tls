#!/usr/bin/env python3
# -*- coding: utf-8 -*-
copywrite = """# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import configparser
import logging

from awacs.aws import Action, Allow, Statement, Principal, PolicyDocument
from troposphere import Template, Ref, Output
from troposphere.iam import Role, ServiceLinkedRole, Policy
from troposphere.codebuild import Artifacts, Environment, Source, Project, ProjectTriggers

logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def build_project(template=Template(), section=None, project_name=None, raw_env=None, service_role: str=None) -> Template:
    template.set_version('2010-09-09')
    # artifacts = Artifacts(Type='S3', Name='s2n-codebuild-artifact-bucket', Location='s2n-codebuild-artifact-bucket')
    artifacts = Artifacts(Type='NO_ARTIFACTS')
    env_list = list()

    try:
        logging.debug(f'raw_env is {raw_env}')
        env = raw_env.split(' ')
    except AttributeError:
        env = config.get(section, 'env').split(' ')
        logging.debug(f'Section is {section}')

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
    project_triggers = ProjectTriggers(
        Webhook=True,
    )

    project_id = project = Project(
        project_name,
        Artifacts=artifacts,
        Environment=environment,
        Name=project_name,
        ServiceRole=service_role,
        Source=source,
        SourceVersion=config.get(section, 'source_version'),
        BadgeEnabled=True,
        DependsOn=service_role,
        Triggers=project_triggers,
    )
    template.add_resource(project)
    template.add_output([Output(f"CodeBuildProject{project_name}", Value=Ref(project_id))])

def build_role(template=Template(), section="CFNRole", project_name:str=None, **kwargs) -> Ref:
    """ Build a role with an inline policy. """
    account_number = config.get(section, 'account_number')
    template.set_version('2010-09-09')
    assert project_name
    project_name+='Role'
    role_id = template.add_resource(
        Role(
            project_name,
            AssumeRolePolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[
                            Action("sts", "AssumeRole")
                        ],
                        Principal=Principal("Service", "codebuild.amazonaws.com")
                    )
                ]
            ),
            Policies=[
                Policy(
                    PolicyName="inline_policy_snapshots_cw_logs",
                    PolicyDocument=PolicyDocument(
                        Id="inline_policy_snapshots_cw_logs",
                        Version="2012-10-17",
                        Statement=[
                            Statement(
                                Effect=Allow,
                                Action=[
                                    Action("logs", "CreateLogGroup"),
                                    Action("logs", "CreateLogStream"),
                                    Action("logs", "PutLogEvents"),
                                ],
                                Resource=[f"arn:aws:logs:*:{account_number}:*"]
                            )
                        ]
                    )
                ),
            ],
        )
    )
    template.add_output([Output(project_name, Value=Ref(role_id))])
    return Ref(role_id)

def build_s3_cache(template=Template(), section=None, **kwargs) -> Template:
    """ Create/Manage the s3 bucket for use by CodeBuild Cache    """
    # TODO: Add s3 bucket.
    pass

def main(**kwargs):
    """ Create the CFN template and either write to screen or update/create boto3. """
    codebuild = Template()
    
    build_s3_cache(template=codebuild)

    for job in config.sections():
        if 'CodeBuild:' in job:
            job_title = job.split(':')[1]
            service_role = build_role(template=codebuild, project_name=job_title).to_dict()
            # Pull the env out of the section, and use the snippet for the other values.
            if 'snippet' in config[job]:
                build_project(template=codebuild, project_name=job_title, section=config.get(job, 'snippet'),\
                              service_role=service_role['Ref'], raw_env=config.get(job, 'env'))
            else:
                build_project(template=codebuild, project_name=job_title, section=job, service_role=service_role['Ref'])

    with(open("cfn/codebuild_test_projects.yml", 'w')) as fh:
        fh.write(codebuild.to_json())

    if args.dry_run:
        logging.debug('Dry Run: wrote cfn file, but not calling AWS.')
    else:
        print('Boto functionality goes here.')


if __name__ == '__main__':
    # Parse  options
    parser = argparse.ArgumentParser(description='Creates AWS CodeBuild Project CloudFormation files ' + \
                                                 'based on a simple config')
    parser.add_argument('--config', type=str, default="codebuild.config", help='The config filename to create the '
                                                                               'CodeBuild projects')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true', help='Output CFN to stdout; Do not call AWS')
    args = parser.parse_args()

    config = configparser.RawConfigParser()
    logging.debug(f'Try to load config file {args.config}')
    config.read(args.config)
    assert config.get('CFNRole', 'account_number')
    main(args=args, config=config)
