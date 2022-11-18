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
import configparser
import hashlib
import json
import logging
import os
import random
import sys
import time

import boto3
from awacs.aws import Action, Allow, Statement, Principal, PolicyDocument
from awacs.sts import AssumeRole
from botocore import exceptions
from troposphere import GetAtt, Template, Ref, Output
from troposphere.codebuild import Artifacts, Environment, Source, Project
from troposphere.events import Rule, Target
from troposphere.iam import Role, Policy

logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def build_cw_event(template=Template, project_name=None, role=None, target_job=None, hour=12, minute=0, input_json=None):
    """ Create a CloudWatch Event to run a CodeBuild Project. """
    # CloudFormation doesn't allow underscores
    project_name = project_name.replace('_', '')

    # target_job is only expected in the case where multiple events are pointed at the same target.
    # Use the project name as the dependency otherwise.
    if not target_job:
        target_job = project_name

    # input_json is used to pass additional ENV variables to the codebuild job.
    if input_json:
        project_target = Target(
            f"{project_name}Target",
            Arn=GetAtt(target_job, "Arn"),
            RoleArn=GetAtt(role, "Arn"),
            Input=json.dumps(input_json),
            Id=f"{project_name}CWid"
        )
    else:
        project_target = Target(
            f"{project_name}Target",
            Arn=GetAtt(target_job, "Arn"),
            RoleArn=GetAtt(role, "Arn"),
            Id=f"{project_name}CWid"
        )

    Rule(f"{project_name}Rule",
         template=template,
         Name=f"{project_name}Event",
         Description="scheduled run Build with CloudFormation",
         Targets=[project_target],
         State='ENABLED',
         # Run at the top of hour.
         ScheduleExpression=f"cron({minute} {hour} * * ? *)",
         DependsOn=target_job
         )


def build_cw_cb_role(template, config, role_name="s2nEventsInvokeCodeBuildRole"):
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
                                "arn:aws:codebuild:{region}:{account_number}:project/*".format(
                                    region=config.get('Global', 'aws_region'),
                                    account_number=config.get('CFNRole', 'account_number')),
                            ]
                        )
                    ]
                )
            )
            ]
        )
    )
    return role_id


def build_github_role(template, config, role_name="s2nCodeBuildGithubRole"):
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
                        Principal=Principal("Service", ["codebuild.amazonaws.com"]),
                        Action=[Action("sts", "AssumeRole")],
                    )
                ]
            ),
        )
    )


def build_artifacts(identifier: str, s3_bucketname: str) -> Artifacts:
    """ CodeBuild Artifact and Secondary Artifact creation. """
    artifact = Artifacts(
        Name=f"{identifier}Artifact",
        ArtifactIdentifier=identifier,
        EncryptionDisabled=True,
        Location=s3_bucketname,
        NamespaceType='NONE',  # NOTE: case sensitive
        OverrideArtifactName=False,
        Packaging='ZIP',  # NOTE: case sensitive
        Type='S3')  # NOTE: case sensitive
    return artifact


def build_project(template=Template(), section=None, project_name=None, raw_env=None,
                  service_role: str = None):
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

    # Put the current account number into the ECR image path.
    if 'AWS_AN' in config.get(section, 'image'):
        config.set(section, 'image', config.get(section, 'image').replace('AWS_AN', get_account_number()))

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


def build_codebuild_role(config, template=Template(), project_name: str = None, **kwargs) -> Ref:
    """ Build a role with a CodeBuild managed policy. """
    assert project_name
    role_name = project_name + 'Role'

    region = config.get("Global", "aws_region")
    account_number = config.get("CFNRole", "account_number")

    # Create a policy to Allow CodeBuild to write to s3 for Artifact storage/retrieval.
    # This should be an AWS Managed Policy, but here we are.
    policies = [Policy(
        PolicyName=f"CodeBuildArtifactPolicy",
        PolicyDocument=PolicyDocument(
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[Action("s3", "PutObject"),
                            Action("s3", "GetObject"),
                            Action("s3", "GetObjectVersion"),
                            Action("s3", "GetBucketAcl"),
                            Action("s3", "GetBucketLocation")],
                    Resource=[
                        "arn:aws:s3:::s2n-build-artifacts/*",
                    ]
                ),
                Statement(
                    Effect=Allow,
                    Action=[Action("logs", "CreateLogGroup"),
                            Action("logs", "CreateLogStream"),
                            Action("logs", "PutLogEvents")],
                    Resource=[
                        "arn:aws:logs:{region}:{account_number}:log-group:/aws/codebuild/{project}:*".format(
                            region=region, account_number=account_number, project=project_name),
                    ]
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("codecommit", "BatchGet*"),
                        Action("codecommit", "BatchDescribe*"),
                        Action("codecommit", "Describe*"),
                        Action("codecommit", "EvaluatePullRequestApprovalRules"),
                        Action("codecommit", "Get*"),
                        Action("codecommit", "List*"),
                        Action("codecommit", "GitPull"),
                    ],
                    Resource=["*"],
                ),
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
            role_name,
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

    template.add_output([Output(role_name, Value=Ref(role_id))])
    return Ref(role_id)


def display_change_set(description):
    """Not the greatest display, but this doesn't require any additional dependencies."""
    for change in description['Changes']:
        items = []
        for k, v in change['ResourceChange'].items():
            if type(v) is list:
                v = str(v)
            q = f"\n\t{k:<20} {v:>10}"
            items.append(q)

        logging.info("Summary of changes: {}".format("".join(items)))


def modify_existing_stack(client, config, codebuild):
    """Modify and exist Codebuild project's CloudFormation stack"""
    stack_name = config.get("Global", "stack_name")

    # ChangeSetNames are required to start with an Alphabetic character, and to be unique.
    # Prefixing the hashed timed with an 'A' gets it done.
    change_set_name = "A" + hashlib.sha256(bytes(time.asctime().encode('utf-8'))).hexdigest()

    client.create_change_set(
        StackName=stack_name,
        TemplateBody=codebuild.to_yaml(),
        Capabilities=["CAPABILITY_IAM"],
        ChangeSetName=change_set_name)

    logging.info(f"Waiting for change set {change_set_name}")
    waiter = client.get_waiter('change_set_create_complete')
    waiter.wait(StackName=stack_name, ChangeSetName=change_set_name, WaiterConfig={"Delay": 3, "MaxAttempt": 3})

    description = client.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    display_change_set(description)

    key = input('\nDo these changes make sense? [Y/n]')
    if key != "Y":
        logging.info("Exiting without executing change set")
        client.delete_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        return

    logging.info(f"Executing {change_set_name}")
    exc = client.execute_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name)

    waiter = client.get_waiter('stack_update_complete')
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 5, "MaxAttempt": 6})
    logging.info(f"Update completed: {exc}")


def create_new_stack(client, config, codebuild):
    """Create a new CloudFormation stack for the Codebuild project"""
    try:
        result = client.create_stack(
            StackName=config.get("Global", "stack_name"),
            TemplateBody=codebuild.to_yaml(),
            Capabilities=["CAPABILITY_IAM"])
        logging.info("Creating stack {}".format(result['StackId']))
    except client.exceptions.AlreadyExistsException as e:
        logging.error("Stack already exists, you must use the --modify-existing flag to update a stack")


def validate_cfn(boto_client: boto3.client, cfn_template: str):
    """ Call validate_template with boto. """
    try:
        response = boto_client.validate_template(TemplateBody=cfn_template)
        logging.debug(f"CloudFormation Template validation response: {response}")
        logging.info('CloudFormation template validation complete.')
    except exceptions.ClientError as e:
        raise SystemExit(f"Failed: {e}")


def get_account_number():
    # Look up the AWS account number.
    return boto3.client('sts').get_caller_identity().get('Account')


def main(args, config):
    """ Create the CFN template and do stuff with said template. """
    codebuild = Template()
    codebuild.set_version('2010-09-09')
    # Create a single CloudWatch Event role to allow codebuild:startBuild
    cw_event_role = build_cw_cb_role(codebuild, config)
    temp_yaml_filename = args.output_dir + "/s2n_codebuild_projects.yml"

    # Role used by GitHub Actions.
    if config.has_option('Global', 'create_github_role') and config.getboolean('Global', 'create_github_role'):
        build_github_role(codebuild, config)

    # Walk the config file, adding each stanza to the Troposphere template.
    for job in config.sections():
        if ':' in job:
            job_title = job.split(':')[1]
        if 'CodeBuild:' in job:
            service_role = build_codebuild_role(config, template=codebuild, project_name=job_title).to_dict()

            # Pull the env out of the section, and use the snippet for the other values.
            # Note: only env is over-ridden with snippets.
            if 'snippet' in config[job]:
                build_project(template=codebuild, project_name=job_title, section=config.get(job, 'snippet'),
                              service_role=service_role['Ref'], raw_env=config.get(job, 'env'))
            else:
                build_project(template=codebuild, project_name=job_title, section=job, service_role=service_role['Ref'])

            # Scheduled runs triggered by CloudWatch.
            build_cw_event(template=codebuild, project_name=job_title, role=cw_event_role)
        if 'CloudWatchEvent' in job:
            # CloudWatch input allows us to over-ride environment variables passed to codebuild.
            cw_input = json.loads(config.get(job, 'input'))
            # Note that for Cloudwatch need to reference an existing CodeBuild Job.
            build_cw_event(template=codebuild, project_name=job_title, target_job=config.get(job, 'build_job_name'),
                           role=cw_event_role,
                           hour=config.get(job, 'start_time'), input_json=cw_input)
        if 'ScheduledTemplate' in job:
            # Use a template within our config to create a list of scheduled CloudWatch events.
            # Example
            # [ScheduledTemplate:tests/fuzz/]
            # start_time: 05:00
            # jobnamesuffix: afl
            # build_job_name: s2nFuzzAFLScheduled
            # input: {"environmentVariablesOverride": [{"name": "FUZZ_TESTS","value": TESTNAME}]}

            # tests/fuzz is the path to *test.c files, relative to the root of gitrepo
            # start_time: scheduled UTC runtime of job
            # jobnamesuffix: appended to the TESTNAME to make it uniq
            # build_job_name: The existing CodeBuild job to use as the target for the scheduled run
            # input: Over-ride environment variable JSON string

            schedule_templates, test_name_list = [], []

            # use the fileglob from the job name
            try:
                test_file_list = os.listdir(job_title)
            except:
                raise OSError(f'failed to read from {job_title}')
            for i in list(filter(lambda x: ('test.c' in x), test_file_list)):
                test_name_list.append(i.split('.')[:1][0])
            cw_input = config.get(job, 'input')

            for test_name in test_name_list:
                # Make the case consistent, Camel with s2n lowered.
                casefix = test_name.split('s2n')[1:][0].title()
                casefix = 's2n' + casefix
                # Randomize the minute, between 0-9, that schedule jobs start to avoid being throttled.
                build_cw_event(template=codebuild,
                               project_name=str(casefix + config.get(job, 'job_name_suffix').title()),
                               target_job=config.get(job, 'build_job_name'),
                               role=cw_event_role,
                               hour=config.get(job, 'start_time'),
                               minute=random.randrange(0,9),
                               input_json=cw_input.replace('TESTNAME', test_name))

    # Write out a CloudFormation template.  This is ephemeral and is not used again.
    with(open(temp_yaml_filename, 'w')) as fh:
        fh.write(codebuild.to_yaml())
        logging.info(f"Wrote cfn yaml file to {temp_yaml_filename}")

    if args.noop:
        logging.info("Respecting noop, Done.")
        return
    else:
        # Fire up the boto, exit gracefully if the user doesn't have creds setup.
        client = boto3.client('cloudformation', region_name=config.get('Global', 'aws_region'))
        try:
            validate_cfn(client, codebuild.to_yaml())
        except exceptions.NoCredentialsError:
            raise SystemExit(f"Something went wrong with your AWS credentials;  Exiting.")

        # Default to not making changes
        if not args.production:
            logging.info('Production flag not set, skipping mutating behavior.')
            return

        if args.modify_existing is True:
            modify_existing_stack(client, config, codebuild)
        else:
            create_new_stack(client, config, codebuild)


if __name__ == '__main__':
    # Parse  options
    parser = argparse.ArgumentParser(description='Creates AWS CodeBuild Project CloudFormation files ' +
                                                 'based on a simple config',
                                     epilog="Additional reserved words used in the config files: " +
                                            'AWS_AN: For customer codebuild images ECR URL, lookup the AWS account ' +
                                            'number from the current session. ' +
                                            'TESTTNAME: When using a ScheduledTemplate, this value will be replaced ' +
                                            'with file names looked up from the filesystem.  See code for a sample.')
    parser.add_argument('--config', type=str, default="codebuild.config", help='The config filename to create the '
                                                                               'CodeBuild projects')
    parser.add_argument('--production', dest='production', action='store_true', default=False,
                        help='Validate CloudFormation yaml and create resources.')
    parser.add_argument('--modify-existing', dest='modify_existing', action='store_true', default=False,
                        help='Modify existing stack.')
    parser.add_argument('--noop', dest='noop', action='store_true',
                        help='Create a local CFN yaml- but do no validation.')
    parser.add_argument('--output-dir', dest='output_dir', default='cfn', help="Directory to write CFN files")
    args = parser.parse_args()
    if not os.path.exists(args.config):
        raise FileNotFoundError(f"Config file not found {args.config}")

    config = configparser.RawConfigParser()

    # The snippets/boilerplate should always be included.
    config.read('common.config')
    config.read(args.config)
    if not config.get('CFNRole', 'account_number'):
        raise configparser.NoSectionError("Couldn't read the common.config, run from the codebuild dir.")

    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)

    if not os.path.isdir(args.output_dir):
        logging.error("Output directory is not actually a directory")
        sys.exit(1)

    main(args=args, config=config)
