FROM ubuntu:14.04

ENV TERM=ansi
RUN apt-get -y install software-properties-common && \
    apt-add-repository ppa:brightbox/ruby-ng && \
    apt-get update
RUN apt-get -y install curl libssl-dev python-pip ruby2.3 && \
    gem install bundler

COPY codebuild codebuild
RUN codebuild/bin/install_sidetrail_dependencies.sh && \
    mkdir -p /sidetrail-install-dir && \
    codebuild/bin/install_sidetrail.sh /sidetrail-install-dir

CMD ['/codebuild/bin/run_sidetrail.sh','/sidetrail-install-dir','/s2n']
