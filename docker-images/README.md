### Docker images

We'd like to make it faster and easier to setup a development environment for s2n using [Docker](https://www.docker.com/) containers.

All of the following commands assume you have Docker setup and running, have permissions, and are in the s2n/docker-images directory of the [s2n](https://github.com/awslabs/s2n) repo.
The Makefile in this directory wraps some convenient commands.

### Building

If you'd like to build the container:

```
make build
```

### Publishing

We don't currently make containers available publicly.  The makefile contains a way
 to login to AWS ECR, where images can be stored privately.
If you set the REPOSITORY_URI ahead of time, you don't need to re-tag the image (step 2).

 ```
 make login
 docker tag <lastimage> <ECR_URL>:ubuntu_18.04_gcc9
 docker push <ECR_URL>:ubuntu_18.04_gcc9
 ```



### Running

Currently the makefile attempts to present the s2n folder to the container.  On some platforms
you must explicitly give docker permission to share folders.  If you have an already built container on ECR, be sure to set the REPOSITORY_URI, e.g. `export REPOSITORY_URI=$AWS_ACCOUNTNUMBER.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images`

```
make run
```
