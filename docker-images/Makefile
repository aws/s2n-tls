REPOSITORY_URI ?= awslabs/s2n-dev

build:
	@cp -R ../codebuild/ ./codebuild/
	@REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build
