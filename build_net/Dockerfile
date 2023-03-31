# Base images 基础镜像 
FROM ubuntu:18.04 
#由于tzdata 20.04.1的bug改用18.04

#RUN 执行以下命令 
RUN apt-get update \
&& apt-get install -y sudo \
&& apt-get install -y vim iproute2 traceroute autoconf make g++ libpcap-dev

#查看
CMD tail -f /dev/null