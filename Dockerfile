FROM crpi-39y3wyxf42ksj3ss.cn-hangzhou.personal.cr.aliyuncs.com/bin-analyzer/base:1.0.1

ADD . /opt/MegaRacTool

WORKDIR /opt/
RUN git clone https://github.com/npitre/cramfs-tools
WORKDIR /opt/cramfs-tools
RUN make && make install
WORKDIR /opt/
RUN apt update
RUN pip3.13 install ipython semgrep loguru numpy xxhash PyYAML cstruct capstone ubi_reader python-lzo jefferson
RUN apt install p7zip p7zip-full cramfsswap squashfs-tools sleuthkit liblzma-dev liblzo2-dev cabextract
RUN wget https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-5/sasquatch_1.0_amd64.deb -O /opt/sasquatch.deb
RUN dpkg -i /opt/sasquatch.deb

WORKDIR /opt/MegaRacTool