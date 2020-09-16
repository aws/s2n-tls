# Makefile for wrapping docker commands
/etc/os-release:
	@sudo yum install -y lsb-release
openssl:
	@sudo yum install -y openssl11-static
python3:
	@sudo yum install -y python3 python3-devel python3-pip
gcc: python3
	@sudo yum install -y gcc
libffi:
	@sudo yum install -y libffi-devel
/usr/local/bin/docker-compose: gcc libffi openssl /etc/os-release
	@sudo python3 -m pip install docker-compose
	@sudo chmod 755 /usr/local/bin/docker-compose


run_al2:
	@docker run --user s2n-dev -tiv "$$(cd ../..;pwd)/s2n":/s2n 024603541914.dkr.ecr.us-west-2.amazonaws.com/linux-docker-images:amazonlinux_2_openssl-1.1.1_gcc7

pull_al2:
	@docker pull $(REPOSITORY_URI):amazonlinux_2_openssl-1.1.1_gcc7
push_al2:
	@docker push $(REPOSITORY_URI):amazonlinux_2_openssl-1.1.1_gcc7
