FROM crpi-39y3wyxf42ksj3ss.cn-hangzhou.personal.cr.aliyuncs.com/bin-analyzer/base:1.0.1

ADD . /opt/MegaRacTool

WORKDIR /opt/
RUN git clone https://github.com/npitre/cramfs-tools
WORKDIR /opt/cramfs-tools
RUN make
RUN mv /opt/cramfs-tools/cramfsck /usr/local/bin/
RUN mv /opt/cramfs-tools/mkcramfs /usr/local/bin/
WORKDIR /opt/
RUN apt update
RUN apt install -y p7zip p7zip-full cramfsswap squashfs-tools sleuthkit liblzma-dev liblzo2-dev cabextract
RUN pip3.13 install ipython semgrep loguru numpy xxhash PyYAML cstruct capstone ubi_reader python-lzo jefferson
RUN wget https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-5/sasquatch_1.0_amd64.deb -O /opt/sasquatch.deb
RUN dpkg -i /opt/sasquatch.deb

WORKDIR /opt/MegaRacTool