REPOSITORY_URI ?= awslabs/s2n-dev
SHELL=/bin/bash
DOCKER_COMPOSE:=$(shell which docker-compose)

.PHONEY: all
all: clean build

setup:
	@cp -fR ../codebuild/ ./codebuild/

.PHONEY: build clean
build: setup
	@REPOSITORY_URI=$(REPOSITORY_URI) $(DOCKER_COMPOSE) build
run:
	@REPOSITORY_URI=$(REPOSITORY_URI) $(DOCKER_COMPOSE) run ubuntu_18.04_gcc9
veryclean:
	docker system prune --volumes -f
clean:
	@rm -rf ./codebuild
login:
	@eval $$(aws ecr get-login --no-include-email);
