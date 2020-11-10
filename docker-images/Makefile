REPOSITORY_URI ?= awslabs/s2n-dev

include al2/Makefile
include ubuntu/Makefile
DOCKER_COMPOSE={shell which docker-compose}
setup:
	@cp -fR ../codebuild/ ./codebuild/

.PHONEY: build
build: setup
	REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build $@

veryclean:
	@docker system prune --volumes -f
clean:
	@rm -rf ./codebuild
login:
	@eval $$(aws ecr get-login --no-include-email);
