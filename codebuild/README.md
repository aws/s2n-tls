### CodeBuild script info

#### Design

- How does CodeBuild decide what to install/test ?
   To match with Travis and minimize rewriting, the environment variables passed to the job
   dictate what is installed and which tests get run.
- Why not build docker images with the dependencies layered in ?
  This is the end goal: get tests running in CodeBuild first, then optimize the containers where it makes sense.

#### Dep tree

General flow of the CodeBuild Test Projects

- buildspec_{OS}.yml
    - codebuild/bin/install_default_dependencies.sh
        - codebuild/bin/install_clang.sh
        - codebuild/bin/install_libFuzzer.sh
        - codebuild/bin/install_openssl_1_1_1.sh
        - codebuild/bin/install_openssl_1_0_2.sh
        - codebuild/bin/install_openssl_1_0_2_fips.sh
        - codebuild/bin/install_cppcheck.sh
        - codebuild/bin/install_libressl.sh
        - codebuild/bin/install_python.sh
        - codebuild/bin/install_gnutls.sh
        - codebuild/bin/install_saw.sh
        - codebuild/bin/install_z3_yices.sh
        - codebuild/bin/install_sslyze.sh
        - codebuild/bin/install_sidetrail_dependencies.sh
    - codebuild/bin/s2n_codebuild.sh
        - codebuild/bin/s2n_override_paths.sh
        - codebuild/bin/run_cppcheck.sh
        - codebuild/bin/copyright_mistake_scanner.sh
        - codebuild/bin/run_kwstyle.sh
        - codebuild/bin/cpp_style_comment_linter.sh
        - codebuild/bin/run_ctverif.sh
        - codebuild/bin/run_sidetrail.sh
        - codebuild/bin/grep_simple_mistakes.sh
    - codebuild/bin/s2n_after_codebuild.sh
        - curl -s https://codecov.io/bash


### Usage to setup Projects

To bootstrap the CodeBuild jobs, the python script:
```
./create_project --dry-run
```

- Use CloudFormation to create the stack with the generated template.
- Open the CodeBuild projects in the console and setup the Source correctly, using your OTP credentials to connect to Github

### Notes on moving from Travis-ci

- Install_clang from Travis is using google chromium clang commit from 2017- which requires python2.7 (EOL); updated for CodeBuild.
- CodeBuild's environment is more restrictive than Travis- these jobs require elevated privilege to function.
- Warning message from the fuzzer about test speed appear in CodeBuild output, but not in Travis-CI with the same test (See comments on AWS forums about a difference in ANSI TERM support); this also affects colorized output.
- macOS/OSX platform files were not copied because CodeBuild does not support macOS builds.
