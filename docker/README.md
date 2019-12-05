### Custom docker images for s2n testing

This is a work in progress to automate image creation.

As an example, to build Ubuntu 19.04 with OpenSSL1.1.1 locally:

```
$ gen_compose.py
$ REPOSITORY_URI=localhost docker-compose build ubuntu_19.04_OpenSSL_1_1_1-stable
```

The final workflow for this approach would be:

- Update gen_compose to add/remove OS flavors, etc
- regenerate the docker-compose file
- submit a PR with changes
- Approved PR merge triggers a CodePipeline job
- CodePipeline runs child CodeBuild jobs, 
  - recreate docker images
  - upload to private ECR instance

