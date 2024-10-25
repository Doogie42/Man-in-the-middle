FROM ubuntu

RUN apt upgrade -y && apt update -y && apt install -y make gcc net-tools inetutils-ping iproute2 curl bmon procps
CMD ["tail", "-f", "/dev/null"]