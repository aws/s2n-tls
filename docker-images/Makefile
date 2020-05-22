REPOSITORY_URI ?= awslabs/s2n-dev

.PHONY : ubuntu
ubuntu:
	@cp -R ../codebuild/ ./codebuild/
	@REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build ubuntu_18.04_openssl-1.1.1_gcc9

.PHONY : amazonlinux
amazonlinux:
	cp -R ../codebuild/ ./codebuild/
	REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build amazonlinux_2_openssl-1.1.1_gcc9

