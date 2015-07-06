FROM ubuntu:14.04
MAINTAINER Tarun Bhardwaj <tarun.bhardwaj@fulfil.io>

RUN apt-get update && \
    apt-get install -y build-essential libssl-dev libffi-dev python-dev python-pip

ADD . /opt/token-auth/
WORKDIR /opt/token-auth

RUN pip install -r requirements.txt
CMD ["python", "application.py"]
