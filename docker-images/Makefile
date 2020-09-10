REPOSITORY_URI ?= awslabs/s2n-dev

.PHONY : ubuntu
ubuntu:
	@cp -R ../codebuild/ ./codebuild/
	@REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build ubuntu_18.04_openssl-1.1.1_gcc9


/etc/os-release:
	@yum install 
openssl:
	@yum install -y openssl11-static
python3:
	@yum install -y python3 python3-dev python3-pip
gcc:
	@yum install -y gcc
libffi:
	@yum install -y libffi-devel
/usr/local/bin/docker-compose: gcc python3 libffi openssl
	@pip install docker-compose
	@chmod 755 /usr/local/bin/docker-compose

.PHONY : amazonlinux
amazonlinux2: /usr/local/bin/docker-compose
	cp -R ../codebuild/ ./codebuild/
	REPOSITORY_URI=$(REPOSITORY_URI) docker-compose build amazonlinux_2_openssl-1.1.1_gcc9

