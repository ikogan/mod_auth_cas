FROM ubuntu-upstart:latest

RUN apt-get update; apt-get install -y apache2 apache2-threaded-dev libtool autoconf check libcurl4-openssl-dev gdb vim lsof curl

COPY container-startup.sh /usr/sbin/container-startup.sh

RUN chmod +x /usr/sbin/container-startup.sh

EXPOSE 22 80 443

ENTRYPOINT /usr/sbin/container-startup.sh
