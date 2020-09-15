# Makefile for wrapping docker commands
REPOSITORY_URI ?= 024603541914.dkr.ecr.us-west-2.amazonaws.com/linux

ifeq ($(shell uname -p),aarch64)
include al2/Makefile
endif

.PHONY : ubuntu
ubuntu:
	@cp -R ../codebuild/ ./codebuild/
	@REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build ubuntu_18.04_openssl-1.1.1_gcc9

.PHONY : al2
al2: /usr/local/bin/docker-compose
	cp -fR ../codebuild/ ./codebuild/
	REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build amazonlinux_2_openssl-1.1.1_gcc7

veryclean:
	docker system prune --volumes -f
clean:
	rm -rf ./codebuild

release:
	@{ set -e; \
	export AWS_DEFAULT_REGION=us-west-2;\
	eval $$(aws ecr get-login --no-include-email);\
	docker push $(REPOSITORY_URI):amazonlinux_2_openssl-1.1.1_gcc7;\
	}

pullal2:
	@docker pull $(REPOSITORY_URI):amazonlinux_2_openssl-1.1.1_gcc7
