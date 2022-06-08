FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ=Asia/Karachi

RUN apt update

RUN apt upgrade -y

RUN apt install -y  build-essential

RUN apt install -y libtool

RUN apt install -y git

RUN apt install -y pkg-config

RUN apt install -y cmake

RUN git clone https://github.com/wolfSSL/wolfssl.git

RUN cd wolfssl && ./autogen.sh && ./configure --enable-curve25519 --enable-eccencrypt --enable-aesctr --enable-x963kdf --enable-compkey && make -j$(nproc) && make install
