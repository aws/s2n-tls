### CodeBuild script info

#### Design

- How does CodeBuild decide what to install/test ?
   Historically the environment variables passed to the job
   dictate what is installed and which tests get run. CodeBuild has a pattern where environment
   variables can be over-ridden by CloudWatch events or batch jobs, so in some cases the CodeBuild job definition
   is generic or filled with placeholders (e.g. s2nFuzzScheduled).
- Why not build docker images with the dependencies layered in ?
  This is the end goal: get tests running in CodeBuild first, then optimize the containers where it makes sense.

#### Dep tree

General flow of the CodeBuild Test Projects

- buildspec_{OS}.yml
    - codebuild/install_default_dependencies.sh
        - codebuild/install_clang.sh
        - codebuild/install_libFuzzer.sh
        - codebuild/install_openssl_1_1_1.sh
        - codebuild/install_openssl_1_0_2.sh
        - codebuild/install_openssl_1_0_2_fips.sh
        - codebuild/install_libressl.sh
        - codebuild/install_python.sh
        - codebuild/install_gnutls.sh
        - codebuild/install_saw.sh
        - codebuild/install_z3_yices.sh
        - codebuild/install_sslyze.sh
    - codebuild/s2n_codebuild.sh
        - codebuild/s2n_override_paths.sh
        - codebuild/copyright_mistake_scanner.sh
        - codebuild/run_kwstyle.sh
        - codebuild/cpp_style_comment_linter.sh
        - codebuild/run_ctverif.sh
        - codebuild/run_sidetrail.sh
        - codebuild/grep_simple_mistakes.sh


### Usage to setup Projects

Using your favorite virtualenv, install the following dependencies:
```
pip install -r requirements.txt
```

To bootstrap the CodeBuild jobs, the python script:
```
# Verify your config is correct
./create_project.py --config the-config-file.config

# If this is a new stack, commit the changes
./create_project.py --config the-config-file.config --production

# If the stack already exists, then use a change set for the existing stack
./create_project.py --config the-config-file.config --production --modify-existing
```

If you are modifying an existing stack then a list of changes will be displayed and
you have the option to accept or reject that change set.

```
ubuntu:codebuild/ $ ./create_project.py --config codebuild-integv2.config --production --modify-existing
INFO:root:Wrote cfn yaml file to cfn/s2n_codebuild_projects.yml
INFO:botocore.credentials:Found credentials in environment variables.
INFO:root:CloudFormation template validation complete.
INFO:root:Waiting for change set A2d385d4f0fcd217fff42e8a0cf3d51bd34a542e916524018b13176413410c2ab
INFO:root:Summary of changes:
    Action                   Modify
    LogicalResourceId    s2nIntegrationV2OpenSSL111Gcc9Role
    PhysicalResourceId   integv2s2nCodeBuildTests-s2nIntegrationV2OpenSSL11-161F84G7NJWVC
    ResourceType         AWS::IAM::Role
    Replacement               False
    Scope                ['Properties']
    Details              [{'Target': {'Attribute': 'Properties', 'Name': 'Policies', 'RequiresRecreation': 'Never'}, 'Evaluation': 'Static', 'ChangeSource': 'DirectModification'}]

Do these changes make sense? [Y/n]Y
INFO:root:Executing A2d385d4f0fcd217fff42e8a0cf3d51bd34a542e916524018b13176413410c2ab
INFO:root:Update completed
```

- Use CloudFormation to create the stack with the generated template.
- Open the CodeBuild projects in the console and setup the Source correctly, using your OTP credentials to connect to Github

### Words about CodeBuild instance size and concurrency

The [AWS Codebuild](https://docs.aws.amazon.com/codebuild/latest/userguide/limits.html) docs list the number of concurrent jobs at 60.
With extensive testing, we've learned this number appears to be weighted based on [instance size](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-compute-types.html) (or provisioning limits), so running all tests on the largest possible instances will reduce actual concurrency.  Additionally provisioning time is currently longer for larger instances, so there is a time penalty that might not be recovered by using a larger instance for short lived tests.

### Batch Builds

The `spec/buildspec_omnibus_batch.yml` contains a complete list of all CodeBuild jobs.  In the future, this will replace the individual jobs created by the create_project.py script.

The broken out batch jobs: fuzz, integration and general, are created with the script create_batch.sh, which uses jq to parse out the jobs by title.

### Notes on moving from Travis-ci

- Install_clang from Travis is using google chromium clang commit from 2017- which requires python2.7 (EOL); updated for CodeBuild.
- CodeBuild's environment is more restrictive than Travis- these jobs require elevated privilege to function.
- Warning message from the fuzzer about test speed appear in CodeBuild output, but not in Travis-CI with the same test (See comments on AWS forums about a difference in ANSI TERM support); this also affects colorized output.
- macOS/OSX platform files were not copied because CodeBuild does not support macOS builds.


### Querying CodeBuild projects

Here is a sample of how to double check the size of the build hosts, as an example.  AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for an associated AWS account will need to be set for this to work, as well as a file called jobs, listing the names of all the CodeBuild jobs you'd like to check.


```
for i in $(cat jobs); do echo -e "$i\t";aws codebuild batch-get-projects --name "$i" |jq '.projects[].environment.computeType'; done
```
