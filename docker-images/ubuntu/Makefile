# Makefile for wrapping docker commands

run_ubuntu18: ubuntu18
	@docker run --user s2n-dev -tiv "$$(cd ../..;pwd)/s2n":/s2n 024603541914.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images:ubuntu_18.04_openssl-1.1.1_gcc9

pull_ubuntu18:
	@docker pull $(REPOSITORY_URI):ubuntu_18.04_openssl-1.1.1_gcc9
push_ubuntu18:
	@docker push $(REPOSITORY_URI):ubuntu_18.04_openssl-1.1.1_gcc9
