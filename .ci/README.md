# CI for s2n
We use prebuilt docker images for all of our AWS CodeBuild builds for speed and
consistency.

## Setup
 To setup the images for local testing or testing in your own AWS account see
the platform specific `README` in docker_images/*.

Once you have the docker images uploaded to AWS Elastic Container Registry you
can setup the AWS CodeBuild projects that use the custom image with the
appropriate buildspec files in codebuild/spec/*.