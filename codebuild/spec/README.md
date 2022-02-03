### CodeBuild Buildspec files

CodeBuild supports two ways of getting a jobs configuration: as part of the git repository, or inline.

Due to security issues around running CodeBuild jobs
with external contributors spec files, many of our CodeBuild spec files are being inlined.

The inline directory has buildspecs that are just for reference/backup and do not actually affect running jobs.

