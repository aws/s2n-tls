# Makefile for wrapping docker commands
export REPOSITORY_URI ?= 024603541914.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images

include al2/Makefile
include ubuntu/Makefile

.PHONY : ubuntu18
ubuntu18:
	@cp -fR ../codebuild/ ./codebuild/
	@REPOSITORY_URI=$(REPOSITORY_URI) /usr/local/bin/docker-compose build ubuntu_18.04_openssl-1.1.1_gcc9

.PHONY : al2
al2: /usr/local/bin/docker-compose
	@cp -fR ../codebuild/ ./codebuild/
	@REPOSITORY_URI=$(REPOSITORY_URI) /usr/local/bin/docker-compose build amazonlinux_2_openssl-1.1.1_gcc7

veryclean:
	@docker system prune --volumes -f
clean:
	@rm -rf ./codebuild
login:
	@eval $$(aws ecr get-login --no-include-email);
