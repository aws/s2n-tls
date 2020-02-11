FROM ubuntu:14.04

RUN apt-get -y install software-properties-common
RUN apt-add-repository ppa:brightbox/ruby-ng
RUN apt-get update
RUN apt-get -y install libssl-dev python-pip ruby2.3
RUN gem install bundler

ADD codebuild codebuild
RUN codebuild/bin/install_sidetrail_dependencies.sh
RUN mkdir -p /sidetrail-install-dir
RUN codebuild/bin/install_sidetrail.sh /sidetrail-install-dir

ADD . s2n
CMD /s2n/codebuild/bin/run_sidetrail.sh /sidetrail-install-dir /s2n
#CMD tail -f /dev/null
