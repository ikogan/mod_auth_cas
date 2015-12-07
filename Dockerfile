FROM ubuntu-upstart:latest

RUN apt-get update; apt-get install -y apache2-threaded-dev check libcurl4-openssl-dev

EXPOSE 22 80 443

ENTRYPOINT /bin/bash
